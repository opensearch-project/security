/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.api.migrate;

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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.search.ClearScrollRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchScrollRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
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
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.resources.ResourceSharingIndexHandler;
import org.opensearch.security.resources.sharing.CreatedBy;
import org.opensearch.security.resources.sharing.Recipient;
import org.opensearch.security.resources.sharing.Recipients;
import org.opensearch.security.resources.sharing.ResourceSharing;
import org.opensearch.security.resources.sharing.ShareWith;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * This REST api allows REST admins to migrate resource-sharing information from plugin indices to the resource-sharing indices managed by security plugin.
 * @apiNote Only super-admins or REST admins can invoke this api.
 * We skip migration of records with no valid creator(user).
 * Defines:
 *  - POST `_plugins/_security/api/resources/migrate`
 *      {
 *          source_index: "abc",                                    // name of plugin index
 *          username_path: "/path/to/username/node",                // path to user-name in resource document in the plugin index
 *          backend_roles_path: "/path/to/user_backend-roles/node"  // path to backend-roles in resource document in the plugin index
 *          default_owner: "<user-name>"                            // default owner when username_path is not available
 *          default_access_level: "<some-default-access-level>"     // default access-level at which sharing records should be created
 *      }
 *   - Response:
 *      200 OK Migration Complete. Migrate X, defaultOwner Y, failed Z // migrate -> successful migration count, defaultOwner -> records with no creator info, failed -> records that failed to migrate
 */
public class MigrateResourceSharingInfoApiAction extends AbstractApiAction {

    private static final Logger LOGGER = LogManager.getLogger(MigrateResourceSharingInfoApiAction.class);

    private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(new Route(POST, "/resources/migrate")));

    private final ResourceSharingIndexHandler sharingIndexHandler;
    private final ResourcePluginInfo resourcePluginInfo;

    public MigrateResourceSharingInfoApiAction(
        ClusterService clusterService,
        ThreadPool threadPool,
        SecurityApiDependencies securityApiDependencies,
        ResourceSharingIndexHandler sharingIndexHandler,
        ResourcePluginInfo resourcePluginInfo
    ) {
        super(Endpoint.RESOURCE_SHARING, clusterService, threadPool, securityApiDependencies);
        this.sharingIndexHandler = sharingIndexHandler;
        this.requestHandlersBuilder.configureRequestHandlers(this::migrateApiRequestHandlers);
        this.resourcePluginInfo = resourcePluginInfo;
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
     *      4. Returns an object of the source index name, the default owner name, the default access level and the list of source docs.
     */
    private ValidationResult<ValidationResultArg> loadCurrentSharingInfo(RestRequest request, Client client) throws IOException {
        JsonNode body = Utils.toJsonNode(request.content().utf8ToString());

        String sourceIndex = body.get("source_index").asText();
        String userNamePath = body.get("username_path").asText();
        String backendRolesPath = body.get("backend_roles_path").asText();
        String defaultOwner = body.get("default_owner").asText();
        JsonNode node = body.get("default_access_level");
        Map<String, String> typeToDefaultAccessLevel = Utils.toMapOfStrings(node);
        String typePath = null;
        if (body.has("type_path")) {
            typePath = body.get("type_path").asText();
        } else {
            LOGGER.info("No type_path provided, assuming single resource-type for all records.");
            if (typeToDefaultAccessLevel.size() > 1) {
                String badRequestMessage = "type_path must be provided when multiple resource types are specified in default_access_level.";
                return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(badRequestMessage));
            }
        }
        if (!resourcePluginInfo.getResourceIndicesForProtectedTypes().contains(sourceIndex)) {
            String badRequestMessage = "Invalid resource index " + sourceIndex + ".";
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(badRequestMessage));
        }

        for (String type : typeToDefaultAccessLevel.keySet()) {
            String defaultAccessLevelForType = typeToDefaultAccessLevel.get(type);
            LOGGER.info("Default access level for resource type [{}] is [{}]", type, typeToDefaultAccessLevel.get(type));
            // check that access level exists for given resource-index
            if (resourcePluginInfo.indexByType(type) == null) {
                String badRequestMessage = "Invalid resource type " + type + ".";
                return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(badRequestMessage));
            }
            var accessLevels = resourcePluginInfo.flattenedForType(type).actionGroups();
            if (!accessLevels.contains(defaultAccessLevelForType)) {
                LOGGER.error(
                    "Invalid access level {} for resource sharing for resource type [{}]. Available access-levels are [{}]",
                    defaultAccessLevelForType,
                    type,
                    accessLevels
                );
                String badRequestMessage = "Invalid access level "
                    + defaultAccessLevelForType
                    + " for resource sharing for resource type ["
                    + type
                    + "]. Available access-levels are ["
                    + accessLevels
                    + "]";
                return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(badRequestMessage));
            }
        }

        // need to stash context because source index may be a system index
        try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
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

                    String type;
                    if (typePath != null) {
                        type = rec.at(typePath.startsWith("/") ? typePath : ("/" + typePath)).asText(null);
                    } else {
                        type = typeToDefaultAccessLevel.keySet().iterator().next();
                    }

                    results.add(new SourceDoc(id, username, backendRoles, type));
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
            return ValidationResult.success(new ValidationResultArg(sourceIndex, defaultOwner, typeToDefaultAccessLevel, results));
        }
    }

    /**
     * This method:
     *      1. Parses existing sharing info to a new ResourceSharing records
     *      2. Indexes the new record into corresponding resource-sharing index
     */
    private ValidationResult<MigrationStats> createNewSharingRecords(ValidationResultArg sourceInfo) throws IOException {
        AtomicInteger migratedCount = new AtomicInteger();
        AtomicInteger skippedExisting = new AtomicInteger();
        AtomicReference<Set<String>> skippedNoType = new AtomicReference<>();
        skippedNoType.set(new HashSet<>());
        AtomicReference<Set<String>> defaultOwner = new AtomicReference<>();
        defaultOwner.set(new HashSet<>());
        AtomicInteger failureCount = new AtomicInteger();

        List<SourceDoc> docs = sourceInfo.sourceDocs;
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

            // 2) skip if no type
            String type = doc.type;
            if (type == null || type.isEmpty()) {
                LOGGER.debug("Record without associated type, skipping entirely: {}", doc.resourceId);
                skippedNoType.get().add(doc.resourceId);
                migrationStatsLatch.countDown();
                continue;
            }

            try {
                // 3) build CreatedBy
                String username = doc.username;
                if (username == null || username.isEmpty()) {
                    LOGGER.debug(
                        "Record {} without associated user, creating a sharing entry with default owner: {}",
                        doc.resourceId,
                        sourceInfo.defaultOwnerName
                    );
                    username = sourceInfo.defaultOwnerName;
                    defaultOwner.get().add(doc.resourceId);
                }
                CreatedBy createdBy = new CreatedBy(username);

                // 4) build ShareWith
                List<String> backendRoles = doc.backendRoles;
                ShareWith shareWith = null;
                if (!backendRoles.isEmpty()) {
                    Recipients recipients = new Recipients(Map.of(Recipient.BACKEND_ROLES, new HashSet<>(backendRoles)));
                    shareWith = new ShareWith(Map.of(sourceInfo.typeToDefaultAccessLevel.get(doc.type), recipients));
                }

                // 5) index the new record
                ActionListener<ResourceSharing> listener = ActionListener.wrap(entry -> {
                    if (entry != null) {
                        LOGGER.debug(
                            "Successfully migrated a resource sharing entry {} for resource {} within index {}",
                            entry,
                            resourceId,
                            sourceInfo.sourceIndex
                        );
                        migratedCount.getAndIncrement();
                    } else {
                        LOGGER.debug(
                            "Skipping migration of resource sharing record for resource {} within index {} as an entry already exists",
                            resourceId,
                            sourceInfo.sourceIndex
                        );
                        skippedExisting.getAndIncrement();
                    }
                    migrationStatsLatch.countDown();
                }, e -> {
                    LOGGER.debug(e.getMessage());
                    failureCount.getAndIncrement();
                    migrationStatsLatch.countDown();
                });
                ResourceSharing.Builder builder = ResourceSharing.builder()
                    .resourceId(resourceId)
                    .createdBy(createdBy)
                    .shareWith(shareWith);
                ResourceSharing sharingInfo = builder.build();
                sharingIndexHandler.indexResourceSharing(sourceInfo.sourceIndex, sharingInfo, true, listener);
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
            "Migration complete. migrated %d; skippedNoType %s; skippedExisting %s; failed %d",
            migratedCount.get(),
            skippedNoType.get().size(),
            skippedExisting.get(),
            failureCount.get()
        );
        MigrationStats stats = new MigrationStats(summary, defaultOwner.get(), skippedNoType.get());
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
                        return ImmutableSet.of(
                            "source_index",
                            "username_path",
                            "backend_roles_path",
                            "default_owner",
                            "default_access_level"
                        );
                    }

                    @Override
                    public Map<String, RequestContentValidator.DataType> allowedKeys() {
                        return ImmutableMap.<String, RequestContentValidator.DataType>builder()
                            .put("source_index", RequestContentValidator.DataType.STRING) // name of the resource plugin index
                            .put("username_path", RequestContentValidator.DataType.STRING) // path to resource creator's name
                            .put("backend_roles_path", RequestContentValidator.DataType.STRING) // path to backend_roles
                            .put("type_path", RequestContentValidator.DataType.STRING) // path to resource type
                            .put("default_owner", RequestContentValidator.DataType.STRING) // default owner name for resources without owner
                            .put("default_access_level", RequestContentValidator.DataType.OBJECT) // default access level by type
                            .build();
                    }
                });
            }
        };
    }

    static class SourceDoc {
        final String resourceId;
        final String username;
        final List<String> backendRoles;
        final String type;

        public SourceDoc(String id, String username, List<String> backendRoles, String type) {
            this.resourceId = id;
            this.username = username;
            this.backendRoles = backendRoles;
            this.type = type;
        }
    }

    static class ValidationResultArg {
        final String sourceIndex;
        final String defaultOwnerName;
        final Map<String, String> typeToDefaultAccessLevel;
        final List<SourceDoc> sourceDocs;

        public ValidationResultArg(
            String sourceIndex,
            String defaultOwner,
            Map<String, String> typeToDefaultAccessLevel,
            List<SourceDoc> sourceDocs
        ) {
            this.sourceIndex = sourceIndex;
            this.defaultOwnerName = defaultOwner;
            this.typeToDefaultAccessLevel = typeToDefaultAccessLevel;
            this.sourceDocs = sourceDocs;
        }
    }

    static class MigrationStats implements ToXContentObject {
        private final String summary;
        private final Set<String> resourcesWithDefaultOwner;
        private final Set<String> skippedResourcesWitNoType;

        public MigrationStats(String summary, Set<String> defaultOwner, Set<String> skippedNoType) {
            this.summary = summary;
            this.resourcesWithDefaultOwner = defaultOwner;
            this.skippedResourcesWitNoType = skippedNoType;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            builder.field("summary", summary);
            builder.field("resourcesWithDefaultOwner", resourcesWithDefaultOwner.toArray(new String[0]));
            builder.array("skippedResources", skippedResourcesWitNoType.toArray(new String[0]));
            builder.endObject();
            return builder;
        }
    }
}
