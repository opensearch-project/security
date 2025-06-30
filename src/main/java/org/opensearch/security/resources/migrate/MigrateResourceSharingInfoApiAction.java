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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.lang3.tuple.Triple;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.search.ClearScrollRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchScrollRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.Scroll;
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
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
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
 *  - POST `_plugins/_security/api/resources/migrate`
 *      {
 *          source_index: "abc",                                    // name of plugin index
 *          username_path: "/path/to/username/node",               // path to user-name in resource document in the plugin index
 *          backend_roles_path: "/path/to/user_backend-roles/node"  // path to backend-roles in resource document in the plugin index
 *          default_access_level: "<some-default-access-level>"     // default value that should replace the otherwise ResourceAccessLevels.PLACE_HOLDER assigned to the new ResourceSharing object
 *      }
 *   - Response:
 *      200 OK Migration Complete. Migrate X, skippedNoUser Y, failed Z // migrate -> successful migration count, skippedNoUser -> records with no creator info, failed -> records that failed to migrate
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
            .valid(stats -> { ok(channel, stats); })
            .error((status, toXContent) -> response(channel, status, toXContent));
    }

    /**
     * This method:
     *      1. Pulls "source_index" from request body
     *      2. Does a match_all search (up to 10k) in the "source_index"
     *      3. Create a SourceDoc for each raw doc
     *      4. Returns a triple of the source index name, the default access level and the list of source docs.
     */
    private ValidationResult<Triple<String, String, List<SourceDoc>>> loadCurrentSharingInfo(RestRequest request, Client client)
        throws IOException {
        JsonNode body = Utils.toJsonNode(request.content().utf8ToString());

        String sourceIndex = body.get("source_index").asText();
        String userNamePath = body.get("username_path").asText();
        String backendRolesPath = body.get("backend_roles_path").asText();
        String defaultAccessLevel = body.has("default_access_level") ? body.get("default_access_level").asText() : PLACE_HOLDER;

        List<SourceDoc> results = new ArrayList<>();

        // 1) configure a 1-minute scroll
        Scroll scroll = new Scroll(TimeValue.timeValueMinutes(1L));
        SearchRequest searchRequest = new SearchRequest(sourceIndex).scroll(scroll)
            .source(
                new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()).size(1_000)        // batch size per scroll “page”
            );

        // 2) execute first search
        SearchResponse searchResponse = client.search(searchRequest).actionGet();
        String scrollId = searchResponse.getScrollId();

        // 3) page through until no hits
        while (true) {
            SearchHit[] hits = searchResponse.getHits().getHits();
            if (hits == null || hits.length == 0) {
                break;
            }
            for (SearchHit hit : hits) {
                JsonNode rec = Utils.toJsonNode(hit.getSourceAsString());
                String id = hit.getId();
                String username = rec.at(userNamePath.startsWith("/") ? userNamePath : ("/" + userNamePath)).asText(null);

                // backend_roles as an actual array
                JsonNode backendRolesNode = rec.at(backendRolesPath.startsWith("/") ? backendRolesPath : ("/" + backendRolesPath));
                List<String> backendRoles = new ArrayList<>();
                if (backendRolesNode.isArray()) {
                    for (JsonNode br : backendRolesNode) {
                        backendRoles.add(br.asText());
                    }
                }

                results.add(new SourceDoc(id, username, backendRoles));
            }
            // 4) fetch next batch
            SearchScrollRequest scrollRequest = new SearchScrollRequest(scrollId).scroll(scroll);
            searchResponse = client.searchScroll(scrollRequest).actionGet();
            scrollId = searchResponse.getScrollId();
        }

        // 5) clear the scroll context to free resources
        ClearScrollRequest clear = new ClearScrollRequest();
        clear.addScrollId(scrollId);
        client.clearScroll(clear).actionGet();

        return ValidationResult.success(Triple.of(sourceIndex, defaultAccessLevel, results));
    }

    /**
     * This method:
     *      1. Parses existing sharing info to a new ResourceSharing records
     *      2. Indexes the new record into corresponding resource-sharing index
     */
    private ValidationResult<MigrationStats> createNewSharingRecords(Triple<String, String, List<SourceDoc>> sourceInfo)
        throws IOException {
        AtomicInteger migratedCount = new AtomicInteger();
        AtomicReference<Set<String>> skippedNoUser = new AtomicReference<>();
        skippedNoUser.set(new HashSet<>());
        AtomicInteger failureCount = new AtomicInteger();

        List<SourceDoc> docs = sourceInfo.getRight();
        int total = docs.size();

        CountDownLatch migrationStatsLatch = new CountDownLatch(total);

        for (SourceDoc doc : docs) {
            // 1) get resource ID
            String resourceId = doc.resourceId;
            if (resourceId == null) {
                failureCount.getAndIncrement();
                migrationStatsLatch.countDown();
                continue;
            }

            // 2) skip if no username node
            String username = doc.username;
            if (username == null || username.isEmpty()) {
                LOGGER.debug("Record without associated user, skipping entirely: {}", doc.resourceId);
                skippedNoUser.get().add(doc.resourceId);
                migrationStatsLatch.countDown();
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
                    shareWith = new ShareWith(Map.of(sourceInfo.getMiddle(), recipients));
                }

                // 5) index the new record
                ActionListener<ResourceSharing> listener = ActionListener.wrap(entry -> {
                    LOGGER.debug(
                        "Successfully migrated a resource sharing entry {} for resource {} within index {}",
                        entry,
                        resourceId,
                        sourceInfo.getLeft()
                    );
                    migratedCount.getAndIncrement();
                    migrationStatsLatch.countDown();
                }, e -> {
                    LOGGER.debug(e.getMessage());
                    failureCount.getAndIncrement();
                    migrationStatsLatch.countDown();
                });
                sharingIndexHandler.indexResourceSharing(resourceId, sourceInfo.getLeft(), createdBy, shareWith, listener);
            } catch (Exception e) {
                LOGGER.warn("Failed indexing sharing info for [{}]: {}", resourceId, e.getMessage());
                failureCount.getAndIncrement();
                migrationStatsLatch.countDown();
            }
        }

        // wait for all records to be addressed
        try {
            migrationStatsLatch.await();
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for migration to finish", ie);
        }

        String summary = String.format(
            "Migration complete. migrated %d; skippedNoUser %d; failed %d",
            migratedCount.get(),
            skippedNoUser.get().size(),
            failureCount.get()
        );
        MigrationStats stats = new MigrationStats(summary, skippedNoUser.get());
        return ValidationResult.success(stats);
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
                        return ImmutableSet.of("source_index", "username_path", "backend_roles_path");
                    }

                    @Override
                    public Map<String, RequestContentValidator.DataType> allowedKeys() {
                        return ImmutableMap.<String, RequestContentValidator.DataType>builder()
                            .put("source_index", RequestContentValidator.DataType.STRING) // name of the resource plugin index
                            .put("username_path", RequestContentValidator.DataType.STRING) // path to resource creator's name
                            .put("backend_roles_path", RequestContentValidator.DataType.STRING) // path to backend_roles
                            .put("default_access_level", RequestContentValidator.DataType.STRING) // default access level for the new
                                                                                                  // structure
                            .build();
                    }
                });
            }
        };
    }

    static class SourceDoc {
        String resourceId;
        String username;
        List<String> backendRoles;

        public SourceDoc(String id, String username, List<String> backendRoles) {
            this.resourceId = id;
            this.username = username;
            this.backendRoles = backendRoles;
        }
    }

    static class MigrationStats implements ToXContentObject {
        private final String summary;
        private final Set<String> skippedResources;

        public MigrationStats(String summary, Set<String> skippedResources) {
            this.summary = summary;
            this.skippedResources = skippedResources;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            builder.field("summary", summary);
            builder.array("skippedResources", skippedResources.toArray(new String[0]));
            builder.endObject();
            return builder;
        }
    }
}
