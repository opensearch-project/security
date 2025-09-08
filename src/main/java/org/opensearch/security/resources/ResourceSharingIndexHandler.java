/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.resources;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.ClearScrollRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchScrollRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.index.query.AbstractQueryBuilder;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.MatchAllQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.script.Script;
import org.opensearch.script.ScriptType;
import org.opensearch.search.Scroll;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.resources.api.share.ShareAction;
import org.opensearch.security.spi.resources.sharing.CreatedBy;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.Recipients;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.spi.resources.sharing.ShareWith;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;
import static org.opensearch.core.xcontent.DeprecationHandler.THROW_UNSUPPORTED_OPERATION;

/**
 * This class handles the creation and management of the resource sharing index.
 * It provides methods to create the index, index resource sharing entries along with updates and deletion, retrieve shared resources.
 *
 * @opensearch.experimental
 */
public class ResourceSharingIndexHandler {

    private static final Logger LOGGER = LogManager.getLogger(ResourceSharingIndexHandler.class);

    private final Client client;

    private final ThreadPool threadPool;
    private final ResourcePluginInfo resourcePluginInfo;

    @Inject
    public ResourceSharingIndexHandler(final Client client, final ThreadPool threadPool, final ResourcePluginInfo resourcePluginInfo) {
        this.client = client;
        this.threadPool = threadPool;
        this.resourcePluginInfo = resourcePluginInfo;
    }

    public final static Map<String, Object> INDEX_SETTINGS = Map.of("index.number_of_shards", 1, "index.hidden", "true");

    /**
     * Creates the resource sharing index if it doesn't already exist.
     * This method initializes the index with predefined mappings and settings
     * for storing resource sharing information.
     * The index will be created with the following structure:
     * - source_idx (keyword): The source index containing the original document
     * - resource_id (keyword): The ID of the shared resource
     * - created_by (object): Information about the user who created the sharing
     * - user (keyword): Username of the creator
     * - share_with (object): Access control configuration for shared resources
     * - [action-group] (object): Name of the action-group
     * - users (array): List of users with access
     * - roles (array): List of roles with access
     * - backend_roles (array): List of backend roles with access
     *
     * @throws RuntimeException if there are issues reading/writing index settings
     *                          or communicating with the cluster
     */

    public void createResourceSharingIndicesIfAbsent(Set<String> resourceIndices) {
        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            for (String resourceIndex : resourceIndices) {
                String resourceSharingIndex = getSharingIndex(resourceIndex);
                CreateIndexRequest cir = new CreateIndexRequest(resourceSharingIndex).settings(INDEX_SETTINGS).waitForActiveShards(1);
                ActionListener<CreateIndexResponse> cirListener = ActionListener.wrap(response -> {
                    ctx.restore();
                    LOGGER.info("Resource sharing index {} created.", resourceSharingIndex);
                }, (failResponse) -> {
                    /* Index already exists, ignore and continue */
                    LOGGER.info("Index {} already exists.", resourceSharingIndex);
                });
                this.client.admin().indices().create(cir, cirListener);
            }
        }
    }

    public static String getSharingIndex(String resourceIndex) {
        return resourceIndex + "-sharing";
    }

    /**
     * Updates the visibility of a resource document by replacing its {@code principals} field
     * with the provided list of principals. The update is executed immediately with
     * {@link WriteRequest.RefreshPolicy#IMMEDIATE} to ensure the change is visible in subsequent
     * searches.
     * <p>
     * The supplied {@link ActionListener} will be invoked with the {@link UpdateResponse}
     * on success, or with an exception on failure.
     *
     * @param resourceId     the unique identifier of the resource document to update
     * @param resourceIndex  the name of the index containing the resource
     * @param principals     the list of principals (e.g. {@code user:alice}, {@code role:admin})
     *                       that should be assigned to the resource
     * @param listener       callback that will be notified with the update response or an error
     */
    public void updateResourceVisibility(
        String resourceId,
        String resourceIndex,
        List<String> principals,
        ActionListener<UpdateResponse> listener
    ) {
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            UpdateRequest ur = client.prepareUpdate(resourceIndex, resourceId)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .setDoc(Map.of("all_shared_principals", principals))
                .setId(resourceId)
                .request();

            ActionListener<UpdateResponse> urListener = ActionListener.wrap(response -> {
                ctx.restore();
                LOGGER.info(
                    "Successfully updated visibility of resource {} in index {} to principals {}.",
                    resourceIndex,
                    resourceId,
                    principals
                );
                listener.onResponse(response);
            }, (e) -> {
                LOGGER.error("Failed to update visibility in [{}] for resource [{}]", resourceIndex, resourceId, e);
                listener.onFailure(e);
            });
            client.update(ur, urListener);
        }
    }

    /**
     * Creates or updates a resource sharing record in the dedicated resource sharing index.
     * This method handles the persistence of sharing metadata for resources, including
     * the creator information and sharing permissions.
     *
     * @param resourceId    The unique identifier of the resource being shared
     * @param resourceIndex The source index where the original resource is stored
     * @param createdBy     Object containing information about the user creating/updating the sharing
     * @param shareWith     Object containing the sharing permissions' configuration. Can be null for initial creation.
     *                      When provided, it should contain the access control settings for different groups:
     *                      {
     *                      "action-group": {
     *                      "users": ["user1", "user2"],
     *                      "roles": ["role1", "role2"],
     *                      "backend_roles": ["backend_role1"]
     *                      }
     *                      }
     * @param listener Returns resourceSharing object if the operation was successful, exception otherwise
     * @throws IOException if there are issues with index operations or JSON processing
     */
    public void indexResourceSharing(
        String resourceId,
        String resourceIndex,
        CreatedBy createdBy,
        ShareWith shareWith,
        ActionListener<ResourceSharing> listener
    ) throws IOException {
        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        String resourceSharingIndex = getSharingIndex(resourceIndex);
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            ResourceSharing entry = new ResourceSharing(resourceId, createdBy, shareWith);

            IndexRequest ir = client.prepareIndex(resourceSharingIndex)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .setSource(entry.toXContent(jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .setOpType(DocWriteRequest.OpType.CREATE) // only create if an entry doesn't exist
                .setId(resourceId)
                .request();

            ActionListener<IndexResponse> irListener = ActionListener.wrap(idxResponse -> {
                ctx.restore();
                LOGGER.info("Successfully created {} entry for resource {} in index {}.", resourceSharingIndex, resourceId, resourceIndex);
                updateResourceVisibility(
                    resourceId,
                    resourceIndex,
                    List.of("user:" + createdBy.getUsername()),
                    ActionListener.wrap((updateResponse) -> {
                        LOGGER.debug(
                            "postUpdate: Successfully updated visibility for resource {} within index {}",
                            resourceId,
                            resourceIndex
                        );
                        listener.onResponse(entry);
                    }, (e) -> {
                        LOGGER.error("Failed to create principals field in [{}] for resource [{}]", resourceIndex, resourceId, e);
                        listener.onResponse(entry);
                    })
                );
            }, (e) -> {
                if (ExceptionsHelper.unwrapCause(e) instanceof VersionConflictEngineException) {
                    // already exists → skipping
                    LOGGER.debug("Entry for [{}] already exists in [{}], skipping", resourceId, resourceSharingIndex);
                    listener.onResponse(entry);
                } else {
                    LOGGER.error("Failed to create entry in [{}] for resource [{}]", resourceSharingIndex, resourceId, e);
                    listener.onFailure(e);
                }
            });
            client.index(ir, irListener);
        }
    }

    /**
     * Fetches all resource sharing records that match the specified system index. This method retrieves
     * a get of resource IDs associated with the given system index from the resource sharing index.
     *
     * <p>The method executes the following steps:
     * <ol>
     *   <li>Creates a search request with term query matching the system index</li>
     *   <li>Applies source filtering to only fetch resource_id field</li>
     *   <li>Executes the search with a limit of 10000 documents</li>
     *   <li>Processes the results to extract resource IDs</li>
     * </ol>
     *
     * <p>Example query structure:
     * <pre>
     * {
     *   "query": {
     *     "term": {
     *       "source_idx": "resource_index_name"
     *     }
     *   },
     *   "_source": ["resource_id"],
     *   "size": 10000
     * }
     * </pre>
     *
     * @param resourceIndex The source index to match against the source_idx field
     * @param listener    The listener to be notified when the operation completes.
     *                    The listener receives a set of resource IDs as a result.
     * @apiNote This method:
     * <ul>
     *   <li>Uses source filtering for optimal performance</li>
     *   <li>Performs exact matching on the source_idx field</li>
     *   <li>Returns an empty get instead of throwing exceptions</li>
     * </ul>
     */
    public void fetchAllResourceIds(String resourceIndex, ActionListener<Set<String>> listener) {
        String resourceSharingIndex = getSharingIndex(resourceIndex);
        LOGGER.debug("Fetching all documents asynchronously from {}", resourceSharingIndex);
        Scroll scroll = new Scroll(TimeValue.timeValueMinutes(1L));

        try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
            final SearchRequest searchRequest = new SearchRequest(resourceSharingIndex);
            searchRequest.scroll(scroll);

            MatchAllQueryBuilder query = QueryBuilders.matchAllQuery();

            executeSearchRequest(scroll, searchRequest, query, ActionListener.wrap(resourceIds -> {
                ctx.restore();
                LOGGER.debug("Found {} documents in {}", resourceIds.size(), resourceSharingIndex);
                listener.onResponse(resourceIds);
            }, exception -> {
                LOGGER.error("Search failed while locating all records inside resourceIndex={} ", resourceIndex, exception);
                listener.onFailure(exception);
            }));
        }
    }

    public void fetchAllResourceSharingRecords(String resourceIndex, ActionListener<Set<SharingRecord>> listener) {
        String resourceSharingIndex = getSharingIndex(resourceIndex);
        LOGGER.debug("Fetching all documents asynchronously from {}", resourceSharingIndex);
        Scroll scroll = new Scroll(TimeValue.timeValueMinutes(1L));

        try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
            final SearchRequest searchRequest = new SearchRequest(resourceSharingIndex);
            searchRequest.scroll(scroll);

            MatchAllQueryBuilder query = QueryBuilders.matchAllQuery();

            executeAllSearchRequest(resourceIndex, scroll, searchRequest, query, ActionListener.wrap(recs -> {
                ctx.restore();
                LOGGER.debug("Found {} documents in {}", recs.size(), resourceSharingIndex);
                listener.onResponse(recs);
            }, exception -> {
                LOGGER.error("Search failed while locating all records inside resourceIndex={} ", resourceIndex, exception);
                listener.onFailure(exception);
            }));
        }
    }

    /**
     * Helper method to fetch own and shared document IDs based on action-group match.
     * This method uses scroll API to handle large result sets efficiently.
     *
     *
     * @param resourceIndex The source index to match against the source_idx field
     * @param entities      Set of values to match in the specified Recipient field. Used for logging. ActionGroupQuery is already updated with these values.
     * @param actionGroupQuery The query to match against the action-group field
     * @param listener      The listener to be notified when the operation completes.
     *                      The listener receives a set of resource IDs as a result.
     * @throws RuntimeException if the search operation fails
     * @apiNote This method:
     * <ul>
     *   <li>Uses scroll API with 1-minute timeout</li>
     *   <li>Processes results in batches of 1000 documents</li>
     *   <li>Performs source filtering for optimization</li>
     *   <li>Uses nested queries for accessing array elements</li>
     *   <li>Properly cleans up scroll context after use</li>
     * </ul>
     */
    public void fetchAccessibleResourceIds(
        String resourceIndex,
        Set<String> entities,
        BoolQueryBuilder actionGroupQuery,
        ActionListener<Set<String>> listener
    ) {
        final Scroll scroll = new Scroll(TimeValue.timeValueMinutes(1L));

        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            // Search the RESOURCE INDEX directly (not the *-sharing index)
            SearchRequest searchRequest = new SearchRequest(resourceIndex);
            searchRequest.scroll(scroll);

            // We match any doc whose "principals" contains at least one of the entities
            // e.g., "user:alice", "role:admin", "backend:ops"
            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                .filter(QueryBuilders.termsQuery("all_shared_principals.keyword", entities));

            executeIdCollectingSearchRequest(scroll, searchRequest, boolQuery, ActionListener.wrap(resourceIds -> {
                ctx.restore();
                LOGGER.debug("Found {} accessible resources in {}", resourceIds.size(), resourceIndex);
                listener.onResponse(resourceIds);
            }, exception -> {
                LOGGER.error("Search failed for resourceIndex={}, entities={}", resourceIndex, entities, exception);
                listener.onFailure(exception);
            }));
        }
    }

    /**
     * Executes a search request against the resource index and collects _id values (resource IDs) using scroll.
     *
     * @param scroll        Search scroll context
     * @param searchRequest Initial search request
     * @param query         Query builder for the request
     * @param listener      Listener to receive the collected resource IDs
     */
    private void executeIdCollectingSearchRequest(
        Scroll scroll,
        SearchRequest searchRequest,
        AbstractQueryBuilder<? extends AbstractQueryBuilder<?>> query,
        ActionListener<Set<String>> listener
    ) {
        SearchSourceBuilder ssb = new SearchSourceBuilder().query(query).size(1000).fetchSource(false); // we only need _id

        searchRequest.source(ssb);

        StepListener<SearchResponse> searchStep = new StepListener<>();
        client.search(searchRequest, searchStep);

        searchStep.whenComplete(initialResponse -> {
            Set<String> collectedResourceIds = new HashSet<>();
            String scrollId = initialResponse.getScrollId();
            processScrollIds(collectedResourceIds, scroll, scrollId, initialResponse.getHits().getHits(), listener);
        }, listener::onFailure);
    }

    /**
     * Recursively processes scroll results and collects hit IDs.
     *
     * @param collectedResourceIds Internal accumulator for resource IDs
     * @param scroll               Scroll context
     * @param scrollId             Scroll ID
     * @param hits                 Search hits
     * @param listener             Listener to receive final set of resource IDs
     */
    private void processScrollIds(
        Set<String> collectedResourceIds,
        Scroll scroll,
        String scrollId,
        SearchHit[] hits,
        ActionListener<Set<String>> listener
    ) {
        if (hits == null || hits.length == 0) {
            clearScroll(scrollId, ActionListener.wrap(ignored -> listener.onResponse(collectedResourceIds), listener::onFailure));
            return;
        }

        for (SearchHit hit : hits) {
            // Resource ID is the document _id in the resource index
            collectedResourceIds.add(hit.getId());
        }

        SearchScrollRequest scrollRequest = new SearchScrollRequest(scrollId).scroll(scroll);
        client.searchScroll(
            scrollRequest,
            ActionListener.wrap(
                scrollResponse -> processScrollIds(
                    collectedResourceIds,
                    scroll,
                    scrollResponse.getScrollId(),
                    scrollResponse.getHits().getHits(),
                    listener
                ),
                e -> clearScroll(scrollId, ActionListener.wrap(ignored -> listener.onFailure(e), ex -> {
                    e.addSuppressed(ex);
                    listener.onFailure(e);
                }))
            )
        );
    }

    /**
     * Helper method to fetch own and shared documents based on action-group match.
     * This method uses scroll API to handle large result sets efficiently.
     *
     *
     * @param resourceIndex The source index to match against the source_idx field
     * @param principalsFlat      Set of values to match in the specified Recipient field. Used for logging. ActionGroupQuery is already updated with these values.
     * @param accessQuery The query to match against the action-group field
     * @param listener      The listener to be notified when the operation completes.
     *                      The listener receives a set of resource shairng records as a result.
     * @throws RuntimeException if the search operation fails
     * @apiNote This method:
     * <ul>
     *   <li>Uses scroll API with 1-minute timeout</li>
     *   <li>Processes results in batches of 1000 documents</li>
     *   <li>Performs source filtering for optimization</li>
     *   <li>Uses nested queries for accessing array elements</li>
     *   <li>Properly cleans up scroll context after use</li>
     * </ul>
     */
    public void fetchAccessibleResourceSharingRecords(
        String resourceIndex,
        User user,
        Set<String> principalsFlat,
        BoolQueryBuilder accessQuery,
        ActionListener<Set<SharingRecord>> listener
    ) {
        final Scroll scroll = new Scroll(TimeValue.timeValueMinutes(1L));
        String resourceSharingIndex = getSharingIndex(resourceIndex);
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            SearchRequest searchRequest = new SearchRequest(resourceSharingIndex);
            searchRequest.scroll(scroll);

            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery();

            boolQuery.must(accessQuery);

            executeFlattenedSearchRequestFullRecord(resourceIndex, user, scroll, searchRequest, boolQuery, ActionListener.wrap(recs -> {
                ctx.restore();
                LOGGER.debug("Found {} documents matching the criteria in {}", recs.size(), resourceSharingIndex);
                listener.onResponse(recs);

            }, exception -> {
                LOGGER.error("Search failed for resourceIndex={}, entities={}", resourceIndex, principalsFlat, exception);
                listener.onFailure(exception);

            }));
        }
    }

    /**
     * Fetches a specific resource sharing document by its resource ID and system resourceIndex.
     * This method performs an exact match search and parses the result into a ResourceSharing object.
     *
     * <p>The method executes the following steps:
     * <ol>
     *   <li>Validates input parameters for null/empty values</li>
     *   <li>Creates a search request with a bool query for exact matching</li>
     *   <li>Executes the search with a limit of 1 document</li>
     *   <li>Parses the result using XContent parser if found</li>
     *   <li>Returns null if no matching document exists</li>
     * </ol>
     *
     * <p>Example query structure:
     * <pre>
     * {
     *   "query": {
     *     "bool": {
     *       "must": [
     *         { "term": { "source_idx": "resource_index_name" } },
     *         { "term": { "resource_id": "resource_id_value" } }
     *       ]
     *     }
     *   },
     *   "size": 1
     * }
     * </pre>
     *
     * @param resourceIndex       The source resourceIndex to match against the source_idx field
     * @param resourceId  The resource ID to fetch. Must exactly match the resource_id field
     * @param listener    The listener to be notified when the operation completes.
     *                    The listener receives the parsed ResourceSharing object or null if not found
     * @throws IllegalArgumentException if resourceIndex or resourceId is null or empty
     * @throws RuntimeException         if the search operation fails or parsing errors occur,
     *                                  wrapping the underlying exception
     * @apiNote This method:
     * <ul>
     *   <li>Uses term queries for exact matching</li>
     *   <li>Expects only one matching document per resource ID</li>
     *   <li>Uses XContent parsing for consistent object creation</li>
     *   <li>Returns null instead of throwing exceptions for non-existent documents</li>
     *   <li>Provides detailed logging for troubleshooting</li>
     * </ul>
     * <p>
     * Example usage:
     * <pre>
     * ResourceSharing sharing = fetchDocumentById("myIndex", "resource123");
     * if (sharing != null) {
     *     // Process the resource sharing object
     * }
     * </pre>
     */
    public void fetchSharingInfo(String resourceIndex, String resourceId, ActionListener<ResourceSharing> listener) {
        if (StringUtils.isBlank(resourceIndex) || StringUtils.isBlank(resourceId)) {
            listener.onFailure(new IllegalArgumentException("resourceIndex and resourceId must not be null or empty"));
            return;
        }
        String resourceSharingIndex = getSharingIndex(resourceIndex);
        LOGGER.debug("Fetching document from {}, matching resource_id: {}", resourceSharingIndex, resourceId);

        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {

            GetRequest getRequest = new GetRequest(resourceSharingIndex).id(resourceId);

            client.get(getRequest, ActionListener.wrap(getResponse -> {
                ctx.restore();
                try {
                    if (!getResponse.isExists()) {
                        LOGGER.debug(
                            "No document found in {} matching resource_id: {} and source_idx {}",
                            resourceSharingIndex,
                            resourceId,
                            resourceIndex
                        );
                        listener.onResponse(null);
                        return;
                    }
                    try (
                        XContentParser parser = XContentType.JSON.xContent()
                            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, getResponse.getSourceAsString())
                    ) {
                        parser.nextToken();
                        ResourceSharing resourceSharing = ResourceSharing.fromXContent(parser);
                        resourceSharing.setResourceId(getResponse.getId());

                        LOGGER.debug(
                            "Successfully fetched document from {} matching resource_id: {} and source_idx: {}",
                            resourceSharingIndex,
                            resourceId,
                            resourceIndex
                        );

                        listener.onResponse(resourceSharing);
                    }
                } catch (Exception e) {
                    String failureResponse = "Failed to parse document matching resource_id: "
                        + resourceId
                        + " and source_idx: "
                        + resourceIndex
                        + " from "
                        + resourceSharingIndex;
                    LOGGER.error(failureResponse, e);
                    listener.onFailure(new OpenSearchStatusException(failureResponse, RestStatus.INTERNAL_SERVER_ERROR));
                }
            }, exception -> {
                String failureResponse = "Something went wrong while fetching resource sharing record for resource_id: "
                    + resourceId
                    + " and source_idx: "
                    + resourceIndex
                    + " from "
                    + resourceSharingIndex;
                LOGGER.error(failureResponse, exception);
                listener.onFailure(new OpenSearchStatusException(failureResponse, RestStatus.INTERNAL_SERVER_ERROR));
            }));

        }
    }

    /**
     * Updates the sharing configuration for an existing resource in the resource sharing index.
     * NOTE: This method only grants new access. To remove access use {@link #revoke(String, String, ShareWith, ActionListener)}
     * This method modifies the sharing permissions for a specific resource identified by its
     * resource ID and source index.
     *
     * @param resourceId      The unique identifier of the resource whose sharing configuration needs to be updated
     * @param resourceIndex   The source index where the original resource is stored
     * @param shareWith       Updated sharing configuration object containing access control settings:
     *                        {
     *                        "action-group": {
     *                        "users": ["user1", "user2"],
     *                        "roles": ["role1", "role2"],
     *                        "backend_roles": ["backend_role1"]
     *                        }
     *                        }
     * @param listener        Listener to be notified when the operation completes
     * @throws RuntimeException if there's an error during the update operation
     */
    public void share(String resourceId, String resourceIndex, ShareWith shareWith, ActionListener<ResourceSharing> listener) {
        StepListener<ResourceSharing> sharingInfoListener = new StepListener<>();

        // Fetch resource sharing doc
        fetchSharingInfo(resourceIndex, resourceId, sharingInfoListener);

        // build update script
        sharingInfoListener.whenComplete(sharingInfo -> {
            if (sharingInfo == null) {
                LOGGER.debug("No sharing record found for resource {}", resourceId);
                listener.onResponse(null);
                return;
            }
            for (String accessLevel : shareWith.accessLevels()) {
                Recipients target = shareWith.atAccessLevel(accessLevel);

                sharingInfo.share(accessLevel, target);
            }

            String resourceSharingIndex = getSharingIndex(resourceIndex);
            try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
                IndexRequest ir = client.prepareIndex(resourceSharingIndex)
                    .setId(sharingInfo.getResourceId())
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .setSource(sharingInfo.toXContent(jsonBuilder(), ToXContent.EMPTY_PARAMS))
                    .setOpType(DocWriteRequest.OpType.INDEX)
                    .request();

                ActionListener<IndexResponse> irListener = ActionListener.wrap(idxResponse -> {
                    ctx.restore();
                    LOGGER.info(
                        "Successfully updated {} entry for resource {} in index {}.",
                        resourceSharingIndex,
                        resourceId,
                        resourceIndex
                    );
                    updateResourceVisibility(
                        resourceId,
                        resourceIndex,
                        sharingInfo.getAllPrincipals(),
                        ActionListener.wrap((updateResponse) -> {
                            LOGGER.debug("Successfully updated visibility for resource {} within index {}", resourceId, resourceIndex);
                            listener.onResponse(sharingInfo);
                        }, (e) -> {
                            LOGGER.error("Failed to update principals field in [{}] for resource [{}]", resourceIndex, resourceId, e);
                            listener.onResponse(sharingInfo);
                        })
                    );
                }, (failResponse) -> {
                    LOGGER.error(failResponse.getMessage());
                    listener.onFailure(failResponse);
                });
                client.index(ir, irListener);
            }
        }, listener::onFailure);
    }

    /**
     * Revokes access for specified entities from a resource sharing document. This method removes the specified
     * entities (users, roles, or backend roles) from the existing sharing configuration while preserving other
     * sharing settings.
     *
     * <p>The method performs the following steps:
     * <ol>
     *   <li>Fetches the existing document</li>
     *   <li>Removes specified entities from their respective lists in all sharing groups</li>
     *   <li>Updates the document if modifications were made</li>
     *   <li>Returns the updated resource sharing configuration</li>
     * </ol>
     *
     * <p>Example document structure:
     * <pre>
     * {
     *   "source_idx": "resource_index_name",
     *   "resource_id": "resource_id",
     *   "share_with": {
     *     "action-group": {
     *       "users": ["user1", "user2"],
     *       "roles": ["role1", "role2"],
     *       "backend_roles": ["backend_role1"]
     *     }
     *   }
     * }
     * </pre>
     *
     * @param resourceId      The ID of the resource from which to revoke access
     * @param resourceIndex   The name of the system index where the resource exists
     * @param revokeAccess    A map containing entity list (USER, ROLE, BACKEND_ROLE) and their corresponding
     *                        values to be removed from the sharing configuration
     * @param listener        Listener to be notified when the operation completes
     * @throws IllegalArgumentException if resourceId, resourceIndex is null/empty, or if revokeAccess is null/empty
     * @throws RuntimeException         if the update operation fails or encounters an error
     * @apiNote This method modifies the existing document. If no modifications are needed (i.e., specified
     * entities don't exist in the current configuration), the original document is returned unchanged.
     * @see Recipient
     * @see ResourceSharing
     */
    public void revoke(String resourceId, String resourceIndex, ShareWith revokeAccess, ActionListener<ResourceSharing> listener) {
        if (StringUtils.isBlank(resourceId) || StringUtils.isBlank(resourceIndex) || revokeAccess == null) {
            listener.onFailure(new IllegalArgumentException("resourceId, resourceIndex, and revokeAccess must not be null or empty"));
            return;
        }
        String resourceSharingIndex = getSharingIndex(resourceIndex);

        StepListener<ResourceSharing> sharingInfoListener = new StepListener<>();

        // Fetch the current ResourceSharing document
        fetchSharingInfo(resourceIndex, resourceId, sharingInfoListener);

        // build revoke script
        sharingInfoListener.whenComplete(sharingInfo -> {

            assert sharingInfo != null;
            for (String accessLevel : revokeAccess.accessLevels()) {
                Recipients target = revokeAccess.atAccessLevel(accessLevel);
                LOGGER.debug(
                    "Revoking access for resource {} in {} for entities: {} and accessLevel: {}",
                    resourceId,
                    resourceIndex,
                    target,
                    accessLevel
                );

                sharingInfo.revoke(accessLevel, target);
            }
            try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
                IndexRequest ir = client.prepareIndex(resourceSharingIndex)
                    .setId(sharingInfo.getResourceId())
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .setSource(sharingInfo.toXContent(jsonBuilder(), ToXContent.EMPTY_PARAMS))
                    .setOpType(DocWriteRequest.OpType.INDEX)
                    .request();

                ActionListener<IndexResponse> irListener = ActionListener.wrap(idxResponse -> {
                    ctx.restore();
                    LOGGER.info("Successfully revoked access of {} to resource {} in index {}.", revokeAccess, resourceId, resourceIndex);
                    updateResourceVisibility(
                        resourceId,
                        resourceIndex,
                        sharingInfo.getAllPrincipals(),
                        ActionListener.wrap((updateResponse) -> {
                            LOGGER.debug("Successfully updated visibility for resource {} within index {}", resourceId, resourceIndex);
                            listener.onResponse(sharingInfo);
                        }, (e) -> {
                            LOGGER.error("Failed to update principals field in [{}] for resource [{}]", resourceIndex, resourceId, e);
                            listener.onResponse(sharingInfo);
                        })
                    );
                }, (failResponse) -> {
                    LOGGER.error(failResponse.getMessage());
                    listener.onFailure(failResponse);
                });
                client.index(ir, irListener);
            }
        }, listener::onFailure);
    }

    /**
     * Fetch existing share_with, apply the patch ops in-memory, and update the sharing record.
     * Two ops are supported:
     * 1. share_with -> upgrade or downgrade access; share with new entities
     * 2. revoke -> revoke access for existing entities
     * @param resourceId    id of the resource to apply the patch to
     * @param resourceIndex name of the index where resource is present
     * @param add  the recipients to be shared with
     * @param revoke  the recipients to be revoked with
     * @param listener      listener to be notified in case of success or failure
     */
    public void patchSharingInfo(
        String resourceId,
        String resourceIndex,
        ShareWith add,
        ShareWith revoke,
        ActionListener<ResourceSharing> listener
    ) {

        StepListener<ResourceSharing> sharingInfoListener = new StepListener<>();
        String resourceSharingIndex = getSharingIndex(resourceIndex);

        // Fetch the current ResourceSharing document
        fetchSharingInfo(resourceIndex, resourceId, sharingInfoListener);

        // Apply patch and update the document
        sharingInfoListener.whenComplete(resourceSharing -> {
            ShareWith updatedShareWith = resourceSharing.getShareWith();
            if (updatedShareWith == null) {
                updatedShareWith = new ShareWith(new HashMap<>());
            }
            if (add != null) {
                updatedShareWith = updatedShareWith.add(add);
            }
            if (revoke != null) {
                updatedShareWith = updatedShareWith.revoke(revoke);
            }

            ShareWith cleaned = null;
            if (updatedShareWith != null) {
                ShareWith pruned = updatedShareWith.prune();
                if (!pruned.isPrivate()) {
                    cleaned = pruned; // store only if something non-empty remains
                }
            }

            ResourceSharing updatedSharingInfo = new ResourceSharing(resourceId, resourceSharing.getCreatedBy(), cleaned);

            try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
                // update the record
                IndexRequest ir = client.prepareIndex(resourceSharingIndex)
                    .setId(resourceId)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .setSource(updatedSharingInfo.toXContent(jsonBuilder(), ToXContent.EMPTY_PARAMS))
                    .setOpType(DocWriteRequest.OpType.INDEX)
                    .request();

                client.index(ir, ActionListener.wrap(idxResponse -> {
                    ctx.restore();
                    LOGGER.info(
                        "Successfully updated {} resource sharing info for resource {} in index {}.",
                        resourceSharingIndex,
                        resourceId,
                        resourceIndex
                    );

                    listener.onResponse(updatedSharingInfo);
                }, (e) -> {
                    LOGGER.error(e.getMessage());
                    listener.onFailure(e);
                }));
            }
        }, listener::onFailure);
    }

    /**
     * Deletes resource sharing records that match the specified source index and resource ID.
     * This method performs a delete-by-query operation in the resource sharing index.
     *
     * <p>The method executes the following steps:
     * <ol>
     *   <li>Creates a delete-by-query request with a bool query</li>
     *   <li>Matches documents based on exact source index and resource ID</li>
     *   <li>Executes the delete operation with immediate refresh</li>
     *   <li>Returns the success/failure status based on deletion results</li>
     * </ol>
     *
     * <p>Example document structure that will be deleted:
     * <pre>
     * {
     *   "source_idx": "source_index_name",
     *   "resource_id": "resource_id_value",
     *   "share_with": {
     *     // sharing configuration
     *   }
     * }
     * </pre>
     *
     * @param resourceIndex  The source index to match in the query (exact match)
     * @param resourceId The resource ID to match in the query (exact match)
     * @param listener   The listener to be notified when the operation completes
     * @throws IllegalArgumentException if resourceIndex or resourceId is null/empty
     * @throws RuntimeException         if the delete operation fails or encounters an error
     * @implNote The delete operation uses a bool query with two must clauses to ensure exact matching:
     * <pre>
     * {
     *   "query": {
     *     "bool": {
     *       "must": [
     *         { "term": { "source_idx": resourceIndex } },
     *         { "term": { "resource_id": resourceId } }
     *       ]
     *     }
     *   }
     * }
     * </pre>
     */
    public void deleteResourceSharingRecord(String resourceId, String resourceIndex, ActionListener<Boolean> listener) {
        String resourceSharingIndex = getSharingIndex(resourceIndex);
        LOGGER.debug(
            "Deleting documents asynchronously from {} where source_idx = {} and resource_id = {}",
            resourceSharingIndex,
            resourceIndex,
            resourceId
        );

        // Delete it as super-admin. This method is only called in postDelete handler for resource-index
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            DeleteRequest deleteRequest = new DeleteRequest(resourceSharingIndex, resourceId);

            client.delete(deleteRequest, ActionListener.wrap(deleteResponse -> {
                ctx.restore();
                boolean deleted = DocWriteResponse.Result.DELETED.equals(deleteResponse.getResult());
                if (deleted) {
                    LOGGER.debug("Successfully deleted {} documents from {}", deleted, resourceSharingIndex);
                    listener.onResponse(true);
                } else {
                    LOGGER.debug(
                        "No documents found to delete in {} for source_idx: {} and resource_id: {}",
                        resourceSharingIndex,
                        resourceIndex,
                        resourceId
                    );
                    // No documents were deleted
                    listener.onResponse(false);
                }
            }, failResponse -> {
                LOGGER.error("Failed to delete documents from {}", resourceSharingIndex, failResponse);
                listener.onFailure(failResponse);
            }));

        }
    }

    /**
     * Executes a search request and returns a set of collected resource IDs using scroll.
     *
     * @param scroll        Search scroll context
     * @param searchRequest Initial search request
     * @param query         Query builder for the request
     * @param listener      Listener to receive the collected resource IDs
     */
    private void executeSearchRequest(
        Scroll scroll,
        SearchRequest searchRequest,
        AbstractQueryBuilder<? extends AbstractQueryBuilder<?>> query,
        ActionListener<Set<String>> listener
    ) {
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(query)
            .size(1000)
            .fetchSource(new String[] { "resource_id" }, null);

        searchRequest.source(searchSourceBuilder);

        StepListener<SearchResponse> searchStep = new StepListener<>();
        client.search(searchRequest, searchStep);

        searchStep.whenComplete(initialResponse -> {
            Set<String> collectedResourceIds = new HashSet<>();
            String scrollId = initialResponse.getScrollId();
            processScrollResults(collectedResourceIds, scroll, scrollId, initialResponse.getHits().getHits(), listener);
        }, listener::onFailure);
    }

    private void executeAllSearchRequest(
        String resourceIndex,
        Scroll scroll,
        SearchRequest searchRequest,
        AbstractQueryBuilder<? extends AbstractQueryBuilder<?>> query,
        ActionListener<Set<SharingRecord>> listener
    ) {
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(query)
            .size(1000)
            .fetchSource(new String[] { "resource_id", "created_by", "share_with" }, null);

        searchRequest.source(searchSourceBuilder);

        StepListener<SearchResponse> searchStep = new StepListener<>();
        client.search(searchRequest, searchStep);

        searchStep.whenComplete(initialResponse -> {
            Set<SharingRecord> recs = new HashSet<>();
            String scrollId = initialResponse.getScrollId();
            processScrollResultsParse(null, true, resourceIndex, recs, scroll, scrollId, initialResponse.getHits().getHits(), listener);
        }, listener::onFailure);
    }

    /**
     * Executes a multi-clause query in a flattened fashion to boost performance by almost 20x for large queries.
     * This is specifically to replace multi-match queries for wild-card expansions.
     * Collects accessible resource sharing records.
     * @param scroll        Search scroll context
     * @param searchRequest Initial search request
     * @param filterQuery   Query builder for the request
     * @param listener      Listener to receive the collected resource sharing records
     */
    private void executeFlattenedSearchRequestFullRecord(
        String resourceIndex,
        User user,
        Scroll scroll,
        SearchRequest searchRequest,
        BoolQueryBuilder filterQuery,
        ActionListener<Set<SharingRecord>> listener
    ) {
        // Painless script to emit all share_with principals
        String scriptSource = """
                // handle shared
                if (params._source.share_with instanceof Map) {
                  for (def grp : params._source.share_with.values()) {
                    if (grp.users instanceof List) {
                      for (u in grp.users) {
                        emit("user:" + u);
                      }
                    }
                    if (grp.roles instanceof List) {
                      for (r in grp.roles) {
                        emit("role:" + r);
                      }
                    }
                    if (grp.backend_roles instanceof List) {
                      for (b in grp.backend_roles) {
                        emit("backend:" + b);
                      }
                    }
                  }
                }
            """;

        Script script = new Script(ScriptType.INLINE, "painless", scriptSource, Map.of());

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().derivedField(
            "all_shared_principals",   // flattened runtime field
            "keyword",                 // type
            script
        );

        searchSourceBuilder.query(filterQuery).size(1000);

        searchSourceBuilder.fetchSource(new String[] { "resource_id", "created_by", "share_with" }, null);

        searchRequest.source(searchSourceBuilder);

        StepListener<SearchResponse> searchStep = new StepListener<>();
        client.search(searchRequest, searchStep);
        searchStep.whenComplete(initialResponse -> {
            Set<SharingRecord> recs = new HashSet<>();
            String scrollId = initialResponse.getScrollId();
            processScrollResultsParse(user, false, resourceIndex, recs, scroll, scrollId, initialResponse.getHits().getHits(), listener);
        }, listener::onFailure);
    }

    /**
     * Recursively processes scroll results and collects resource IDs.
     *
     * @param collectedResourceIds Internal accumulator for resource IDs
     * @param scroll               Scroll context
     * @param scrollId             Scroll ID
     * @param hits                 Search hits
     * @param listener             Listener to receive final set of resource IDs
     */
    private void processScrollResults(
        Set<String> collectedResourceIds,
        Scroll scroll,
        String scrollId,
        SearchHit[] hits,
        ActionListener<Set<String>> listener
    ) {
        if (hits == null || hits.length == 0) {
            clearScroll(scrollId, ActionListener.wrap(ignored -> listener.onResponse(collectedResourceIds), listener::onFailure));
            return;
        }

        for (SearchHit hit : hits) {
            Map<String, Object> source = hit.getSourceAsMap();
            if (source != null && source.containsKey("resource_id")) {
                collectedResourceIds.add(source.get("resource_id").toString());
            }
        }

        SearchScrollRequest scrollRequest = new SearchScrollRequest(scrollId).scroll(scroll);
        client.searchScroll(
            scrollRequest,
            ActionListener.wrap(
                scrollResponse -> processScrollResults(
                    collectedResourceIds,
                    scroll,
                    scrollResponse.getScrollId(),
                    scrollResponse.getHits().getHits(),
                    listener
                ),
                e -> clearScroll(scrollId, ActionListener.wrap(ignored -> listener.onFailure(e), ex -> {
                    e.addSuppressed(ex);
                    listener.onFailure(e);
                }))
            )
        );
    }

    /**
     * Recursively processes scroll results and collects resource sharing records.
     *
     * @param resourceSharingRecords Internal accumulator for resource sharing records
     * @param scroll               Scroll context
     * @param scrollId             Scroll ID
     * @param hits                 Search hits
     * @param listener             Listener to receive final set of resource sharing records
     */
    private void processScrollResultsParse(
        User user,
        boolean isAdmin,
        String resourceIndex,
        Set<SharingRecord> resourceSharingRecords,
        Scroll scroll,
        String scrollId,
        SearchHit[] hits,
        ActionListener<Set<SharingRecord>> listener
    ) {
        if (hits == null || hits.length == 0) {
            clearScroll(scrollId, ActionListener.wrap(ignored -> listener.onResponse(resourceSharingRecords), listener::onFailure));
            return;
        }

        for (SearchHit hit : hits) {
            try (
                XContentParser parser = XContentHelper.createParser(
                    NamedXContentRegistry.EMPTY,
                    THROW_UNSUPPORTED_OPERATION,
                    hit.getSourceRef(),
                    XContentType.JSON
                )
            ) {
                parser.nextToken();
                ResourceSharing rs = ResourceSharing.fromXContent(parser);
                boolean canShare = canUserShare(user, isAdmin, rs, resourceIndex);
                resourceSharingRecords.add(new SharingRecord(rs, canShare));
            } catch (Exception e) {
                // TODO: Decide how strict should this failure be:
                // Option A: fail-fast
                // listener.onFailure(e); return;
                // Option B: log & skip bad docs
                LOGGER.warn("Failed to parse resource-sharing doc id={}", hit.getId(), e);
            }
        }

        final SearchScrollRequest scrollReq = new SearchScrollRequest(scrollId).scroll(scroll);
        client.searchScroll(
            scrollReq,
            ActionListener.wrap(
                sr -> processScrollResultsParse(
                    user,
                    isAdmin,
                    resourceIndex,
                    resourceSharingRecords,
                    scroll,
                    sr.getScrollId(),
                    sr.getHits().getHits(),
                    listener
                ),
                e -> clearScroll(scrollId, ActionListener.wrap(ignored -> listener.onFailure(e), ex -> {
                    e.addSuppressed(ex);
                    listener.onFailure(e);
                }))
            )
        );
    }

    /**
     * Clears scroll context after scrolling is complete or on error.
     *
     * @param scrollId Scroll ID to clear
     * @param listener Listener to notify when clearing is done
     */
    private void clearScroll(String scrollId, ActionListener<Void> listener) {
        if (scrollId == null) {
            listener.onResponse(null);
            return;
        }

        ClearScrollRequest clearScrollRequest = new ClearScrollRequest();
        clearScrollRequest.addScrollId(scrollId);
        client.clearScroll(clearScrollRequest, ActionListener.wrap(r -> listener.onResponse(null), e -> {
            LOGGER.warn("Failed to clear scroll context", e);
            listener.onResponse(null);
        }));
    }

    // **** Check whether user can share this record further
    /** Resolve access-level for THIS resource type and check required action. */
    public boolean groupAllows(String resourceIndex, String accessLevel, String requiredAction) {
        String resourceType = resourcePluginInfo.typeByIndex(resourceIndex);
        if (resourceType == null || accessLevel == null || requiredAction == null) return false;
        return resourcePluginInfo.flattenedForType(resourceType).resolve(Set.of(accessLevel)).contains(requiredAction);
    }

    /**
     * Checks whether current user has sharing permission, i.e {@link ShareAction#NAME}
     */
    public boolean canUserShare(User user, boolean isAdmin, ResourceSharing resource, String resourceType) {
        if (resource == null) return false;

        if (isAdmin || resource.isCreatedBy(user.getName())) return true;

        var sw = resource.getShareWith();
        if (sw == null || sw.getSharingInfo().isEmpty()) return false;

        Set<String> users = Set.of(user.getName());
        Set<String> roles = new HashSet<>(user.getSecurityRoles());
        Set<String> backend = new HashSet<>(user.getRoles());

        for (String level : sw.getSharingInfo().keySet()) {
            if (!groupAllows(resourceType, level, ShareAction.NAME)) continue;

            var recips = sw.atAccessLevel(level);
            if (recips == null) continue;

            var u = recips.getRecipients().getOrDefault(Recipient.USERS, Set.of());
            var r = recips.getRecipients().getOrDefault(Recipient.ROLES, Set.of());
            var b = recips.getRecipients().getOrDefault(Recipient.BACKEND_ROLES, Set.of());

            boolean matches = u.contains("*")
                || r.contains("*")
                || b.contains("*")
                || !Collections.disjoint(u, users)
                || !Collections.disjoint(r, roles)
                || !Collections.disjoint(b, backend);

            if (matches) return true;
        }
        return false;
    }

}
