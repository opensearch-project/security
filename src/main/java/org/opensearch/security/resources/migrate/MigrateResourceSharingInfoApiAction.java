/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.migrate;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.dlic.rest.api.AbstractApiAction;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.security.dlic.rest.api.RequestHandler;
import org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator;
import org.opensearch.security.dlic.rest.api.SecurityApiDependencies;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.resources.ResourceSharingIndexHandler;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.spi.resources.sharing.CreatedBy;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.Recipients;
import org.opensearch.security.spi.resources.sharing.ShareWith;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static org.opensearch.security.spi.resources.ResourceAccessLevels.PLACE_HOLDER;

/**
 * This REST api allows REST admins to migrate resources sharing information from plugin indices to the resource-sharing indices managed by security plugin.
 * @apiNote Only super-admins or REST admins can invoke this api.
 * We skip migration of records with no valid creator(user).
 * Defines:
 *  - POST `/resources/migrate`
 *      {
 *          source_index: "abc",                                    // name of plugin index
 *          user.name: "/path/to/username/node",                    // path to user-name in resource document in the plugin index
 *          user.backend_roles: "/path/to/user_backend-roles/node"  // path to backend-roles in resource document in the plugin index
 *      }
 *   - Response:
 *      200 OK Migration Complete. migrate X, skippedNoUser Y, failed Z    // migrate -> successful migration count, skippedNoUser -> records with no creator info, failed -> records that failed to migrate
 */
public class MigrateResourceSharingInfoApiAction extends AbstractApiAction {

    private static final Logger LOGGER = LogManager.getLogger(MigrateResourceSharingInfoApiAction.class);

    private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(new Route(POST, "/resources/migrate")));

    private final ResourceSharingIndexHandler sharingIndexHandler;

    public MigrateResourceSharingInfoApiAction(
        ClusterService clusterService,
        ThreadPool threadPool,
        SecurityApiDependencies securityApiDependencies,
        ResourceSharingIndexHandler sharingIndexHandler
    ) {
        super(Endpoint.RESOURCE_SHARING, clusterService, threadPool, securityApiDependencies);
        this.sharingIndexHandler = sharingIndexHandler;
        this.requestHandlersBuilder.configureRequestHandlers(this::migrateApiRequestHandlers);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType<?> getConfigType() {
        return null;
    }

    private void migrateApiRequestHandlers(RequestHandler.RequestHandlersBuilder b) {
        b.allMethodsNotImplemented().override(POST, this::handleMigrate);
    }

    private void handleMigrate(RestChannel channel, RestRequest request, Client client) throws IOException {
        endpointValidator.createRequestContentValidator()
            .validate(request)
            // 1. read the old sharing docs
            .map(pair -> loadCurrentSharingInfo(request, client))
            // 2. transform and index the new ResourceSharing records
            .map(this::createNewSharingRecords)
            // 3. send the response
            .valid(summary -> { ok(channel, summary); })
            .error((status, toXContent) -> response(channel, status, toXContent));
    }

    /**
     * This method:
     *      1. Pulls "source_index" from the request body
     *      2. Does a match_all search (up to 10k) in the "source_index"
     *      3. Create a SourceDoc for each raw doc
     *      3. Returns the list of source docs.
     */
    private ValidationResult<List<SourceDoc>> loadCurrentSharingInfo(RestRequest request, Client client) throws IOException {
        JsonNode body = Utils.toJsonNode(request.content().utf8ToString());

        String sourceIndex = body.get("source_index").asText();
        String userNamePath = body.get("user.name").asText();
        String backendRolesPath = body.get("user.backend_roles").asText();

        SearchRequest sr = new SearchRequest(sourceIndex);
        sr.source(new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()).size(10_000)); // TODO verify
                                                                                                // this limit
        SearchResponse resp = client.search(sr).actionGet();

        // build a SourceDoc object of id, sourceIndex, username and backendRoles
        List<SourceDoc> results = new ArrayList<>();
        for (SearchHit hit : resp.getHits().getHits()) {
            JsonNode rec = Utils.toJsonNode(hit.getSourceAsString());

            String id = hit.getId();

            String username = rec.at(userNamePath.startsWith("/") ? userNamePath : ("/" + userNamePath)).asText(null);

            // backend_roles → split CSV into a List<String>
            JsonNode backendRolesNode = rec.at(backendRolesPath.startsWith("/") ? backendRolesPath : ("/" + backendRolesPath));
            List<String> backendRoles = new ArrayList<>();
            if (backendRolesNode.isArray() && !backendRolesNode.isEmpty()) {
                for (JsonNode br : backendRolesNode) {
                    backendRoles.add(br.asText());
                }
            }
            results.add(new SourceDoc(id, sourceIndex, username, backendRoles));
        }

        return ValidationResult.success(results);
    }

    /**
     * This method:
     *      1. Parses existing sharing info to a new ResourceSharing records
     *      2. Indexes the new record into corresponding resource-sharing index
     */
    private ValidationResult<String> createNewSharingRecords(List<SourceDoc> sourceDocs) throws IOException {
        int migratedCount = 0;
        int skippedNoUser = 0;
        int failureCount = 0;

        for (SourceDoc doc : sourceDocs) {
            // 1) get resource ID
            String resourceId = doc.resourceId;
            if (resourceId == null) {
                failureCount++;
                continue;
            }

            // 2) skip if no username node
            String username = doc.username;
            if (username == null || username.isEmpty()) {
                LOGGER.warn("Record without associate user, skipping entirely: {}", doc.resourceId);
                skippedNoUser++;
                continue;
            }

            try {
                // 3) build CreatedBy
                CreatedBy createdBy = new CreatedBy(username);

                // 4) build ShareWith
                List<String> backendRoles = doc.backendRoles;
                ShareWith shareWith = null;
                if (!backendRoles.isEmpty()) {
                    Recipients recipients = new Recipients(Map.of(Recipient.BACKEND_ROLES, new HashSet<>(backendRoles)));
                    shareWith = new ShareWith(Map.of(PLACE_HOLDER, recipients));
                }

                // 5) index the new record
                sharingIndexHandler.indexResourceSharing(resourceId, doc.sourceIndex, createdBy, shareWith);
                migratedCount++;
            } catch (Exception e) {
                LOGGER.warn("Failed indexing sharing info for [{}]: {}", resourceId, e.getMessage());
                failureCount++;
            }
        }

        String summary = String.format(
            "Migration complete. migrated %d; skippedNoUser %d; failed %d",
            migratedCount,
            skippedNoUser,
            failureCount
        );
        return ValidationResult.success(summary);
    }

    @Override
    protected EndpointValidator createEndpointValidator() {
        return new EndpointValidator() {
            @Override
            public Endpoint endpoint() {
                return endpoint;
            }

            @Override
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return securityApiDependencies.restApiAdminPrivilegesEvaluator();
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
                    @Override
                    public Object[] params() {
                        return new Object[0];
                    }

                    @Override
                    public Settings settings() {
                        return securityApiDependencies.settings();
                    }

                    @Override
                    public Set<String> mandatoryKeys() {
                        return ImmutableSet.of("source_index", "user.name", "user.backend_roles");
                    }

                    @Override
                    public Map<String, RequestContentValidator.DataType> allowedKeys() {
                        return ImmutableMap.<String, RequestContentValidator.DataType>builder()
                            .put("source_index", RequestContentValidator.DataType.STRING) // name of the resource plugin index
                            .put("user.name", RequestContentValidator.DataType.STRING) // path to resource creator's name
                            .put("user.backend_roles", RequestContentValidator.DataType.STRING) // path to backend_roles
                            .build();
                    }
                });
            }
        };
    }

    static class SourceDoc {
        String resourceId;
        String sourceIndex;
        String username;
        List<String> backendRoles;

        public SourceDoc(String id, String sourceIndex, String username, List<String> backendRoles) {
            this.resourceId = id;
            this.sourceIndex = sourceIndex;
            this.username = username;
            this.backendRoles = backendRoles;
        }
    }
}
