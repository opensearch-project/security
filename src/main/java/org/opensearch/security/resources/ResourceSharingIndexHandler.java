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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.ClearScrollRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchScrollRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.AbstractQueryBuilder;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.MultiMatchQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequest;
import org.opensearch.index.reindex.UpdateByQueryAction;
import org.opensearch.index.reindex.UpdateByQueryRequest;
import org.opensearch.script.Script;
import org.opensearch.script.ScriptType;
import org.opensearch.search.Scroll;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.spi.resources.ShareableResource;
import org.opensearch.security.spi.resources.ShareableResourceParser;
import org.opensearch.security.spi.resources.sharing.CreatedBy;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.spi.resources.sharing.ShareWith;
import org.opensearch.security.spi.resources.sharing.SharedWithActionGroup;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;

/**
 * This class handles the creation and management of the resource sharing index.
 * It provides methods to create the index, index resource sharing entries along with updates and deletion, retrieve shared resources.
 *
 * @opensearch.experimental
 */
public class ResourceSharingIndexHandler {

    private static final Logger LOGGER = LogManager.getLogger(ResourceSharingIndexHandler.class);

    private final Client client;

    private final String resourceSharingIndex;

    private final ThreadPool threadPool;

    public ResourceSharingIndexHandler(final String indexName, final Client client, final ThreadPool threadPool) {
        this.resourceSharingIndex = indexName;
        this.client = client;
        this.threadPool = threadPool;
    }

    public final static Map<String, Object> INDEX_SETTINGS = Map.of(
        "index.number_of_shards",
        1,
        "index.auto_expand_replicas",
        "0-all",
        "index.hidden",
        "true"
    );

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

    public void createResourceSharingIndexIfAbsent(Callable<Boolean> callable) {
        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {

            CreateIndexRequest cir = new CreateIndexRequest(resourceSharingIndex).settings(INDEX_SETTINGS).waitForActiveShards(1);
            ActionListener<CreateIndexResponse> cirListener = ActionListener.wrap(response -> {
                LOGGER.info("Resource sharing index {} created.", resourceSharingIndex);
                if (callable != null) {
                    callable.call();
                }
            }, (failResponse) -> {
                /* Index already exists, ignore and continue */
                LOGGER.info("Index {} already exists.", resourceSharingIndex);
                try {
                    if (callable != null) {
                        callable.call();
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            this.client.admin().indices().create(cir, cirListener);
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
     * @return ResourceSharing Returns resourceSharing object if the operation was successful, null otherwise
     * @throws IOException if there are issues with index operations or JSON processing
     */
    public ResourceSharing indexResourceSharing(String resourceId, String resourceIndex, CreatedBy createdBy, ShareWith shareWith)
        throws IOException {
        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            ResourceSharing entry = new ResourceSharing(resourceIndex, resourceId, createdBy, shareWith);

            IndexRequest ir = client.prepareIndex(resourceSharingIndex)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .setSource(entry.toXContent(jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .setOpType(DocWriteRequest.OpType.CREATE) // only create if an entry doesn't exist
                .request();

            ActionListener<IndexResponse> irListener = ActionListener.wrap(
                idxResponse -> LOGGER.info(
                    "Successfully created {} entry for resource {} in index {}.",
                    resourceSharingIndex,
                    resourceId,
                    resourceIndex
                ),
                (failResponse) -> {
                    LOGGER.error(failResponse.getMessage());
                }
            );
            client.index(ir, irListener);
            return entry;
        } catch (Exception e) {
            LOGGER.error("Failed to create {} entry.", resourceSharingIndex, e);
            throw new OpenSearchStatusException("Failed to create " + resourceSharingIndex + " entry.", RestStatus.INTERNAL_SERVER_ERROR);
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
     * @param pluginIndex The source index to match against the source_idx field
     * @param listener    The listener to be notified when the operation completes.
     *                    The listener receives a set of resource IDs as a result.
     * @apiNote This method:
     * <ul>
     *   <li>Uses source filtering for optimal performance</li>
     *   <li>Performs exact matching on the source_idx field</li>
     *   <li>Returns an empty get instead of throwing exceptions</li>
     * </ul>
     */
    public void fetchAllDocuments(String pluginIndex, ActionListener<Set<String>> listener) {
        LOGGER.debug("Fetching all documents asynchronously from {} where source_idx = {}", resourceSharingIndex, pluginIndex);
        Scroll scroll = new Scroll(TimeValue.timeValueMinutes(1L));

        try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
            final SearchRequest searchRequest = new SearchRequest(resourceSharingIndex);
            searchRequest.scroll(scroll);

            TermQueryBuilder query = QueryBuilders.termQuery("source_idx.keyword", pluginIndex);

            executeSearchRequest(scroll, searchRequest, query, ActionListener.wrap(resourceIds -> {
                LOGGER.debug("Found {} documents in {}", resourceIds.size(), resourceSharingIndex);
                listener.onResponse(resourceIds);

            }, exception -> {
                LOGGER.error("Search failed while locating all records inside pluginIndex={} ", pluginIndex, exception);
                listener.onFailure(exception);

            }));
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    /**
     * Fetches documents withing specified resource index available to given entities.
     *
     * <p>Example query structure:
     * <pre>
     * {
     *   "query": {
     *     "bool": {
     *       "must": [
     *         { "term": { "source_idx": "resource_index_name" } },
     *         {
     *           "bool": {
     *             "should": [
     *               {
     *                 "nested": {
     *                   "path": "share_with.*.Recipient",
     *                   "query": {
     *                     "term": { "share_with.*.Recipient": "entity_value" }
     *                   }
     *                 }
     *               }
     *             ],
     *             "minimum_should_match": 1
     *           }
     *         }
     *       ]
     *     }
     *   },
     *   "_source": ["resource_id"],
     *   "size": 1000
     * }
     * </pre>
     *
     * @param pluginIndex   The source index to match against the source_idx field
     * @param entities      Set of values to match in the specified Recipient field
     * @param recipient     The type recipient {@link Recipient}
     * @param listener      The listener to be notified when the operation completes.
     *                      The listener receives a set of resource IDs as a result.
     * @throws RuntimeException if the search operation fails
     */
    public void fetchDocumentsForAllActionGroups(
        String pluginIndex,
        Set<String> entities,
        String recipient,
        ActionListener<Set<String>> listener
    ) {
        LOGGER.debug(
            "Fetching all documents asynchronously from index: {} accessible by entities {} of type {}",
            pluginIndex,
            entities,
            recipient
        );
        BoolQueryBuilder shouldQuery = QueryBuilders.boolQuery();
        for (String entity : entities) {
            shouldQuery.should(
                QueryBuilders.multiMatchQuery(entity, "share_with.*." + recipient + ".keyword")
                    .type(MultiMatchQueryBuilder.Type.BEST_FIELDS)
            );
        }
        shouldQuery.minimumShouldMatch(1);
        fetchSharedDocuments(pluginIndex, entities, recipient, shouldQuery, listener);
    }

    /**
     * Fetches documents that match the specified system index and have specific access type values.
     * <p>Example query structure:
     * <pre>
     * {
     *   "query": {
     *     "bool": {
     *       "must": [
     *         { "term": { "source_idx": "resource_index_name" } },
     *         {
     *           "bool": {
     *             "should": [
     *               {
     *                 "nested": {
     *                   "path": "share_with.action-group.Recipient",
     *                   "query": {
     *                     "term": { "share_with.action-group.Recipient": "entity_value" }
     *                   }
     *                 }
     *               }
     *             ],
     *             "minimum_should_match": 1
     *           }
     *         }
     *       ]
     *     }
     *   },
     *   "_source": ["resource_id"],
     *   "size": 1000
     * }
     * </pre>
     *
     * @param pluginIndex   The source index to match against the source_idx field
     * @param entities      Set of values to match in the specified Recipient field
     * @param recipient     The type of recipient {@link Recipient}
     * @param actionGroup   The action group to match against the action-group field
     * @param listener      The listener to be notified when the operation completes.
     *                      The listener receives a set of resource IDs as a result.
     */
    public void fetchDocumentsForAGivenActionGroup(
        String pluginIndex,
        Set<String> entities,
        String recipient,
        String actionGroup,
        ActionListener<Set<String>> listener
    ) {
        LOGGER.debug(
            "Fetching documents asynchronously from index: {} by action-group {} accessible by entities {} of type {}",
            pluginIndex,
            actionGroup,
            entities,
            recipient
        );
        BoolQueryBuilder shouldQuery = QueryBuilders.boolQuery();
        for (String entity : entities) {
            shouldQuery.should(QueryBuilders.termQuery("share_with." + actionGroup + "." + recipient + ".keyword", entity));
        }
        shouldQuery.minimumShouldMatch(1);

        fetchSharedDocuments(pluginIndex, entities, recipient, shouldQuery, listener);
    }

    /**
     * Helper method to fetch shared documents based on action-group match.
     * This method uses scroll API to handle large result sets efficiently.
     *
     *
     * @param pluginIndex   The source index to match against the source_idx field
     * @param entities      Set of values to match in the specified Recipient field
     * @param recipient     The type of recipient {@link Recipient}
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
    public void fetchSharedDocuments(
        String pluginIndex,
        Set<String> entities,
        String recipient,
        BoolQueryBuilder actionGroupQuery,
        ActionListener<Set<String>> listener
    ) {

        final Scroll scroll = new Scroll(TimeValue.timeValueMinutes(1L));

        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            SearchRequest searchRequest = new SearchRequest(resourceSharingIndex);
            searchRequest.scroll(scroll);

            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery().must(QueryBuilders.termQuery("source_idx.keyword", pluginIndex));

            boolQuery.must(QueryBuilders.existsQuery("share_with")).must(actionGroupQuery);

            executeSearchRequest(scroll, searchRequest, boolQuery, ActionListener.wrap(resourceIds -> {
                LOGGER.debug("Found {} documents matching the criteria in {}", resourceIds.size(), resourceSharingIndex);
                listener.onResponse(resourceIds);

            }, exception -> {
                LOGGER.error("Search failed for pluginIndex={}, recipient={}, entities={}", pluginIndex, recipient, entities, exception);
                listener.onFailure(exception);

            }));
        } catch (Exception e) {
            LOGGER.error(
                "Failed to initiate fetch from {} for criteria - pluginIndex: {}, recipient: {}, entities: {}",
                resourceSharingIndex,
                pluginIndex,
                recipient,
                entities,
                e
            );
            listener.onFailure(new RuntimeException("Failed to fetch documents: " + e.getMessage(), e));
        }
    }

    /**
     * Fetches documents from the resource sharing index that match a specific field value.
     * This method uses scroll API to efficiently handle large result sets and performs exact
     * matching on both system index and the specified field.
     *
     * <p>The method executes the following steps:
     * <ol>
     *   <li>Validates input parameters for null/empty values</li>
     *   <li>Creates a scrolling search request with a bool query</li>
     *   <li>Processes results in batches using scroll API</li>
     *   <li>Extracts resource IDs from matching documents</li>
     *   <li>Cleans up scroll context after completion</li>
     * </ol>
     *
     * <p>Example query structure:
     * <pre>
     * {
     *   "query": {
     *     "bool": {
     *       "must": [
     *         { "term": { "source_idx": "system_index_value" } },
     *         { "term": { "field_name": "field_value" } }
     *       ]
     *     }
     *   },
     *   "_source": ["resource_id"],
     *   "size": 1000
     * }
     * </pre>
     *
     * @param pluginIndex The source index to match against the source_idx field
     * @param field       The field name to search in. Must be a valid field in the index mapping
     * @param value       The value to match for the specified field. Performs exact term matching
     * @param listener    The listener to be notified when the operation completes.
     *                    The listener receives a set of resource IDs as a result.
     * @throws IllegalArgumentException if any parameter is null or empty
     * @throws RuntimeException         if the search operation fails, wrapping the underlying exception
     * @apiNote This method:
     * <ul>
     *   <li>Uses scroll API with 1-minute timeout for handling large result sets</li>
     *   <li>Performs exact term matching (not analyzed) on field values</li>
     *   <li>Processes results in batches of 1000 documents</li>
     *   <li>Uses source filtering to only fetch resource_id field</li>
     *   <li>Automatically cleans up scroll context after use</li>
     * </ul>
     * <p>
     * Example usage:
     * <pre>
     * Set<String> resources = fetchDocumentsByField("myIndex", "status", "active");
     * </pre>
     */
    public void fetchDocumentsByField(String pluginIndex, String field, String value, ActionListener<Set<String>> listener) {
        if (StringUtils.isBlank(pluginIndex) || StringUtils.isBlank(field) || StringUtils.isBlank(value)) {
            listener.onFailure(new IllegalArgumentException("pluginIndex, field, and value must not be null or empty"));
            return;
        }

        LOGGER.debug("Fetching documents from index: {}, where {} = {}", pluginIndex, field, value);

        final Scroll scroll = new Scroll(TimeValue.timeValueMinutes(1L));

        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            SearchRequest searchRequest = new SearchRequest(resourceSharingIndex);
            searchRequest.scroll(scroll);

            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                .must(QueryBuilders.termQuery("source_idx.keyword", pluginIndex))
                .must(QueryBuilders.termQuery(field + ".keyword", value));

            executeSearchRequest(scroll, searchRequest, boolQuery, ActionListener.wrap(resourceIds -> {
                LOGGER.debug("Found {} documents in {} where {} = {}", resourceIds.size(), resourceSharingIndex, field, value);
                listener.onResponse(resourceIds);
            }, exception -> {
                LOGGER.error("Failed to fetch documents from {} where {} = {}", resourceSharingIndex, field, value, exception);
                listener.onFailure(new RuntimeException("Failed to fetch documents: " + exception.getMessage(), exception));
            }));
        } catch (Exception e) {
            LOGGER.error("Failed to initiate fetch from {} where {} = {}", resourceSharingIndex, field, value, e);
            listener.onFailure(new RuntimeException("Failed to initiate fetch: " + e.getMessage(), e));
        }

    }

    /**
     * Fetches a specific resource sharing document by its resource ID and system index.
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
     * @param pluginIndex The source index to match against the source_idx field
     * @param resourceId  The resource ID to fetch. Must exactly match the resource_id field
     * @param listener    The listener to be notified when the operation completes.
     *                    The listener receives the parsed ResourceSharing object or null if not found
     * @throws IllegalArgumentException if pluginIndexName or resourceId is null or empty
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
    public void fetchDocumentById(String pluginIndex, String resourceId, ActionListener<ResourceSharing> listener) {
        if (StringUtils.isBlank(pluginIndex) || StringUtils.isBlank(resourceId)) {
            listener.onFailure(new IllegalArgumentException("pluginIndex and resourceId must not be null or empty"));
            return;
        }
        LOGGER.debug("Fetching document from index: {}, resourceId: {}", pluginIndex, resourceId);

        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                .must(QueryBuilders.termQuery("source_idx.keyword", pluginIndex))
                .must(QueryBuilders.termQuery("resource_id.keyword", resourceId));

            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(boolQuery).size(1); // There is only one document for
            // a single resource

            SearchRequest searchRequest = new SearchRequest(resourceSharingIndex).source(searchSourceBuilder);

            client.search(searchRequest, new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse searchResponse) {
                    try {
                        SearchHit[] hits = searchResponse.getHits().getHits();
                        if (hits.length == 0) {
                            LOGGER.debug("No document found for resourceId: {} in index: {}", resourceId, pluginIndex);
                            listener.onResponse(null);
                            return;
                        }

                        SearchHit hit = hits[0];
                        try (
                            XContentParser parser = XContentType.JSON.xContent()
                                .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString())
                        ) {
                            parser.nextToken();
                            ResourceSharing resourceSharing = ResourceSharing.fromXContent(parser);

                            LOGGER.debug("Successfully fetched document for resourceId: {} from index: {}", resourceId, pluginIndex);

                            listener.onResponse(resourceSharing);
                        }
                    } catch (Exception e) {
                        LOGGER.error("Failed to parse document for resourceId: {} from index: {}", resourceId, pluginIndex, e);
                        listener.onFailure(
                            new OpenSearchStatusException(
                                "Failed to parse document for resourceId: " + resourceId + " from index: " + pluginIndex,
                                RestStatus.INTERNAL_SERVER_ERROR
                            )
                        );
                    }
                }

                @Override
                public void onFailure(Exception e) {

                    LOGGER.error("Failed to fetch document for resourceId: {} from index: {}", resourceId, pluginIndex, e);
                    listener.onFailure(
                        new OpenSearchStatusException(
                            "Failed to fetch document for resourceId: " + resourceId + " from index: " + pluginIndex,
                            RestStatus.INTERNAL_SERVER_ERROR
                        )
                    );

                }
            });
        } catch (Exception e) {
            LOGGER.error("Failed to fetch document for resourceId: {} from index: {}", resourceId, pluginIndex, e);
            listener.onFailure(
                new OpenSearchStatusException(
                    "Failed to fetch document for resourceId: " + resourceId + " from index: " + pluginIndex,
                    RestStatus.INTERNAL_SERVER_ERROR
                )
            );
        }
    }

    /**
     * Updates the sharing configuration for an existing resource in the resource sharing index.
     * NOTE: This method only grants new access. To remove access use {@link #revokeAccess(String, String, org.opensearch.security.spi.resources.sharing.SharedWithActionGroup.ActionGroupRecipients, Set, String, boolean, ActionListener)}
     * This method modifies the sharing permissions for a specific resource identified by its
     * resource ID and source index.
     *
     * @param resourceId      The unique identifier of the resource whose sharing configuration needs to be updated
     * @param sourceIdx       The source index where the original resource is stored
     * @param requestUserName The user requesting to revoke the resource
     * @param shareWith       Updated sharing configuration object containing access control settings:
     *                        {
     *                        "action-group": {
     *                        "users": ["user1", "user2"],
     *                        "roles": ["role1", "role2"],
     *                        "backend_roles": ["backend_role1"]
     *                        }
     *                        }
     * @param isAdmin         Boolean indicating whether the user requesting to revoke is an admin or not
     * @param listener        Listener to be notified when the operation completes
     * @throws RuntimeException if there's an error during the update operation
     */
    public void updateResourceSharingInfo(
        String resourceId,
        String sourceIdx,
        String requestUserName,
        ShareWith shareWith,
        boolean isAdmin,
        ActionListener<ResourceSharing> listener
    ) {
        XContentBuilder builder;
        Map<String, Object> shareWithMap;
        try {
            builder = XContentFactory.jsonBuilder();
            shareWith.toXContent(builder, ToXContent.EMPTY_PARAMS);
            String json = builder.toString();
            shareWithMap = DefaultObjectMapper.readValue(json, new TypeReference<>() {
            });
        } catch (IOException e) {
            LOGGER.error("Failed to build json content", e);
            listener.onFailure(new OpenSearchStatusException("Failed to build json content", RestStatus.INTERNAL_SERVER_ERROR));
            return;
        }

        StepListener<ResourceSharing> fetchDocListener = new StepListener<>();
        StepListener<Boolean> updateScriptListener = new StepListener<>();
        StepListener<ResourceSharing> updatedSharingListener = new StepListener<>();

        // Fetch resource sharing doc
        fetchDocumentById(sourceIdx, resourceId, fetchDocListener);

        // build update script
        fetchDocListener.whenComplete(currentSharingInfo -> {
            // Check if user can share. At present only the resource creator and admin is allowed to share the resource
            if (!isAdmin && currentSharingInfo != null && !currentSharingInfo.getCreatedBy().getCreator().equals(requestUserName)) {

                LOGGER.error("User {} is not authorized to share resource {}", requestUserName, resourceId);
                listener.onFailure(
                    new OpenSearchStatusException(
                        "User " + requestUserName + " is not authorized to share resource " + resourceId,
                        RestStatus.FORBIDDEN
                    )
                );
            }

            Script updateScript = new Script(ScriptType.INLINE, "painless", """
                if (ctx._source.share_with == null) {
                    ctx._source.share_with = [:];
                }

                for (def entry : params.shareWith.entrySet()) {
                    def actionGroupName = entry.getKey();
                    def newActionGroup = entry.getValue();

                    if (!ctx._source.share_with.containsKey(actionGroupName)) {
                        def newActionGroupEntry = [:];
                        for (def field : newActionGroup.entrySet()) {
                            if (field.getValue() != null && !field.getValue().isEmpty()) {
                                newActionGroupEntry[field.getKey()] = new HashSet(field.getValue());
                            }
                        }
                        ctx._source.share_with[actionGroupName] = newActionGroupEntry;
                    } else {
                        def existingActionGroup = ctx._source.share_with[actionGroupName];

                        for (def field : newActionGroup.entrySet()) {
                            def fieldName = field.getKey();
                            def newValues = field.getValue();

                            if (newValues != null && !newValues.isEmpty()) {
                                if (!existingActionGroup.containsKey(fieldName)) {
                                    existingActionGroup[fieldName] = new HashSet();
                                }

                                for (def value : newValues) {
                                    if (!existingActionGroup[fieldName].contains(value)) {
                                        existingActionGroup[fieldName].add(value);
                                    }
                                }
                            }
                        }
                    }
                }
                """, Collections.singletonMap("shareWith", shareWithMap));

            updateByQueryResourceSharing(sourceIdx, resourceId, updateScript, updateScriptListener);

        }, listener::onFailure);

        // Build & return the updated ResourceSharing
        updateScriptListener.whenComplete(success -> {
            if (!success) {
                LOGGER.error("Failed to update resource sharing info for resource {}", resourceId);
                listener.onResponse(null);
                return;
            }
            // TODO check if this should be replaced by Java in-memory computation (current intuition is that it will be more memory
            // intensive to do it in java)
            fetchDocumentById(sourceIdx, resourceId, updatedSharingListener);
        }, listener::onFailure);

        updatedSharingListener.whenComplete(listener::onResponse, listener::onFailure);
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
     * @param sourceIdx       The name of the system index where the resource exists
     * @param revokeAccess    A map containing entity types (USER, ROLE, BACKEND_ROLE) and their corresponding
     *                        values to be removed from the sharing configuration
     * @param actionGroups     A set of action-groups to revoke access from. If null or empty, access is revoked from all action-groups
     * @param requestUserName The user trying to revoke the accesses
     * @param isAdmin         Boolean indicating whether the user is an admin or not
     * @param listener        Listener to be notified when the operation completes
     * @throws IllegalArgumentException if resourceId, sourceIdx is null/empty, or if revokeAccess is null/empty
     * @throws RuntimeException         if the update operation fails or encounters an error
     * @apiNote This method modifies the existing document. If no modifications are needed (i.e., specified
     * entities don't exist in the current configuration), the original document is returned unchanged.
     * @see Recipient
     * @see ResourceSharing
     */
    public void revokeAccess(
        String resourceId,
        String sourceIdx,
        SharedWithActionGroup.ActionGroupRecipients revokeAccess,
        Set<String> actionGroups,
        String requestUserName,
        boolean isAdmin,
        ActionListener<ResourceSharing> listener
    ) {
        if (StringUtils.isBlank(resourceId) || StringUtils.isBlank(sourceIdx) || revokeAccess == null) {
            listener.onFailure(new IllegalArgumentException("resourceId, sourceIdx, and revokeAccess must not be null or empty"));
            return;
        }

        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {

            LOGGER.debug(
                "Revoking access for resource {} in {} for entities: {} and actionGroups: {}",
                resourceId,
                sourceIdx,
                revokeAccess,
                actionGroups
            );

            StepListener<ResourceSharing> currentSharingListener = new StepListener<>();
            StepListener<Boolean> revokeUpdateListener = new StepListener<>();
            StepListener<ResourceSharing> updatedSharingListener = new StepListener<>();

            // Fetch the current ResourceSharing document
            fetchDocumentById(sourceIdx, resourceId, currentSharingListener);

            // Check permissions & build revoke script
            currentSharingListener.whenComplete(currentSharingInfo -> {
                // Only admin or the creator of the resource is currently allowed to revoke access
                if (!isAdmin && currentSharingInfo != null && !currentSharingInfo.getCreatedBy().getCreator().equals(requestUserName)) {
                    listener.onFailure(
                        new OpenSearchStatusException(
                            "User " + requestUserName + " is not authorized to revoke access to resource " + resourceId,
                            RestStatus.FORBIDDEN
                        )
                    );
                }

                Map<String, Object> revoke = new HashMap<>();
                for (Map.Entry<Recipient, Set<String>> entry : revokeAccess.getRecipients().entrySet()) {
                    revoke.put(entry.getKey().getName(), new ArrayList<>(entry.getValue()));
                }
                List<String> actionGroupsToUse = (actionGroups != null) ? new ArrayList<>(actionGroups) : new ArrayList<>();

                Script revokeScript = new Script(
                    ScriptType.INLINE,
                    "painless",
                    """
                        if (ctx._source.share_with != null) {
                            Set actionGroupsToProcess = new HashSet(params.actionGroups.isEmpty() ? ctx._source.share_with.keySet() : params.actionGroups);

                            for (def actionGroupName : actionGroupsToProcess) {
                                if (ctx._source.share_with.containsKey(actionGroupName)) {
                                    def existingActionGroup = ctx._source.share_with.get(actionGroupName);

                                    for (def entry : params.revokeAccess.entrySet()) {
                                        def recipient = entry.getKey();
                                        def entitiesToRemove = entry.getValue();

                                        if (existingActionGroup.containsKey(recipient) && existingActionGroup[recipient] != null) {
                                            if (!(existingActionGroup[recipient] instanceof HashSet)) {
                                                existingActionGroup[recipient] = new HashSet(existingActionGroup[recipient]);
                                            }

                                            existingActionGroup[recipient].removeAll(entitiesToRemove);

                                            if (existingActionGroup[recipient].isEmpty()) {
                                                existingActionGroup.remove(recipient);
                                            }
                                        }
                                    }

                                    if (existingActionGroup.isEmpty()) {
                                        ctx._source.share_with.remove(actionGroupName);
                                    }
                                }
                            }
                        }
                        """,
                    Map.of("revokeAccess", revoke, "actionGroups", actionGroupsToUse)
                );
                updateByQueryResourceSharing(sourceIdx, resourceId, revokeScript, revokeUpdateListener);

            }, listener::onFailure);

            // Return doc or null based on successful result, fail otherwise
            revokeUpdateListener.whenComplete(success -> {
                if (!success) {
                    LOGGER.error("Failed to revoke access for resource {} in index {} (no docs updated).", resourceId, sourceIdx);
                    listener.onResponse(null);
                    return;
                }
                // TODO check if this should be replaced by Java in-memory computation (current intuition is that it will be more memory
                // intensive to do it in java)
                fetchDocumentById(sourceIdx, resourceId, updatedSharingListener);
            }, listener::onFailure);

            updatedSharingListener.whenComplete(listener::onResponse, listener::onFailure);
        }
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
     * @param sourceIdx  The source index to match in the query (exact match)
     * @param resourceId The resource ID to match in the query (exact match)
     * @param listener   The listener to be notified when the operation completes
     * @throws IllegalArgumentException if sourceIdx or resourceId is null/empty
     * @throws RuntimeException         if the delete operation fails or encounters an error
     * @implNote The delete operation uses a bool query with two must clauses to ensure exact matching:
     * <pre>
     * {
     *   "query": {
     *     "bool": {
     *       "must": [
     *         { "term": { "source_idx": sourceIdx } },
     *         { "term": { "resource_id": resourceId } }
     *       ]
     *     }
     *   }
     * }
     * </pre>
     */
    public void deleteResourceSharingRecord(String resourceId, String sourceIdx, ActionListener<Boolean> listener) {
        LOGGER.debug(
            "Deleting documents asynchronously from {} where source_idx = {} and resource_id = {}",
            resourceSharingIndex,
            sourceIdx,
            resourceId
        );

        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            DeleteByQueryRequest dbq = new DeleteByQueryRequest(resourceSharingIndex).setQuery(
                QueryBuilders.boolQuery()
                    .must(QueryBuilders.termQuery("source_idx.keyword", sourceIdx))
                    .must(QueryBuilders.termQuery("resource_id.keyword", resourceId))
            ).setRefresh(true);

            client.execute(DeleteByQueryAction.INSTANCE, dbq, new ActionListener<>() {
                @Override
                public void onResponse(BulkByScrollResponse response) {

                    long deleted = response.getDeleted();
                    if (deleted > 0) {
                        LOGGER.debug("Successfully deleted {} documents from {}", deleted, resourceSharingIndex);
                        listener.onResponse(true);
                    } else {
                        LOGGER.debug(
                            "No documents found to delete in {} for source_idx: {} and resource_id: {}",
                            resourceSharingIndex,
                            sourceIdx,
                            resourceId
                        );
                        // No documents were deleted
                        listener.onResponse(false);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    LOGGER.error("Failed to delete documents from {}", resourceSharingIndex, e);
                    listener.onFailure(e);

                }
            });
        } catch (Exception e) {
            LOGGER.error("Failed to delete documents from {} before request submission", resourceSharingIndex, e);
            listener.onFailure(e);
        }
    }

    /**
     * Deletes all resource sharing records that were created by a specific user.
     * This method performs a delete-by-query operation to remove all documents where
     * the created_by.user field matches the specified username.
     *
     * <p>The method executes the following steps:
     * <ol>
     *   <li>Validates the input username parameter</li>
     *   <li>Creates a delete-by-query request with term query matching</li>
     *   <li>Executes the delete operation with immediate refresh</li>
     *   <li>Returns the operation status based on number of deleted documents</li>
     * </ol>
     *
     * <p>Example query structure:
     * <pre>
     * {
     *   "query": {
     *     "term": {
     *       "created_by.user": "username"
     *     }
     *   }
     * }
     * </pre>
     *
     * @param name     The username to match against the created_by.user field
     * @param listener The listener to be notified when the operation completes
     * @throws IllegalArgumentException if name is null or empty
     * @implNote Implementation details:
     * <ul>
     *   <li>Uses DeleteByQueryRequest for efficient bulk deletion</li>
     *   <li>Sets refresh=true for immediate consistency</li>
     *   <li>Uses term query for exact username matching</li>
     *   <li>Implements comprehensive error handling and logging</li>
     * </ul>
     * <p>
     * Example usage:
     * <pre>
     * boolean success = deleteAllRecordsForUser("john.doe");
     * if (success) {
     *     // Records were successfully deleted
     * } else {
     *     // No matching records found or operation failed
     * }
     * </pre>
     */
    public void deleteAllRecordsForUser(String name, ActionListener<Boolean> listener) {
        if (StringUtils.isBlank(name)) {
            listener.onFailure(new IllegalArgumentException("Username must not be null or empty"));
            return;
        }

        LOGGER.debug("Deleting all records for user {} asynchronously", name);

        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            DeleteByQueryRequest deleteRequest = new DeleteByQueryRequest(resourceSharingIndex).setQuery(
                QueryBuilders.termQuery("created_by.user", name)
            ).setRefresh(true);

            client.execute(DeleteByQueryAction.INSTANCE, deleteRequest, new ActionListener<>() {
                @Override
                public void onResponse(BulkByScrollResponse response) {
                    long deletedDocs = response.getDeleted();
                    if (deletedDocs > 0) {
                        LOGGER.debug("Successfully deleted {} documents created by user {}", deletedDocs, name);
                        listener.onResponse(true);
                    } else {
                        LOGGER.warn("No documents found for user {}", name);
                        // No documents matched => success = false
                        listener.onResponse(false);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    LOGGER.error("Failed to delete documents for user {}", name, e);
                    listener.onFailure(e);
                }
            });
        } catch (Exception e) {
            LOGGER.error("Failed to delete documents for user {} before request submission", name, e);
            listener.onFailure(e);
        }
    }

    /**
     * Fetches all documents from the specified resource index and deserializes them into the specified class.
     *
     * @param resourceIndex The resource index to fetch documents from.
     * @param parser        The class to deserialize the documents into a specified type defined by the parser.
     * @param listener      The listener to be notified with the set of deserialized documents.
     * @param <T>           The type of the deserialized documents.
     */
    public <T extends ShareableResource> void getResourceDocumentsFromIds(
        Set<String> resourceIds,
        String resourceIndex,
        ShareableResourceParser<T> parser,
        ActionListener<Set<T>> listener
    ) {
        if (resourceIds.isEmpty()) {
            listener.onResponse(new HashSet<>());
            return;
        }

        // stashing Context to avoid permission issues in-case resourceIndex is a system index
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            MultiGetRequest request = new MultiGetRequest();
            for (String id : resourceIds) {
                request.add(new MultiGetRequest.Item(resourceIndex, id));
            }

            client.multiGet(request, ActionListener.wrap(response -> {
                Set<T> result = new HashSet<>();
                try {
                    for (MultiGetItemResponse itemResponse : response.getResponses()) {
                        if (!itemResponse.isFailed() && itemResponse.getResponse().isExists()) {
                            BytesReference sourceAsString = itemResponse.getResponse().getSourceAsBytesRef();
                            XContentParser xContentParser = XContentHelper.createParser(
                                NamedXContentRegistry.EMPTY,
                                LoggingDeprecationHandler.INSTANCE,
                                sourceAsString,
                                XContentType.JSON
                            );
                            T resource = parser.parseXContent(xContentParser);
                            result.add(resource);
                        }
                    }
                    listener.onResponse(result);
                } catch (Exception e) {
                    listener.onFailure(
                        new OpenSearchStatusException("Failed to parse resources: " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR)
                    );
                }
            }, e -> {
                if (e instanceof IndexNotFoundException) {
                    LOGGER.error("Index {} does not exist", resourceIndex, e);
                    listener.onFailure(e);
                } else {
                    LOGGER.error("Failed to fetch resources with ids {} from index {}", resourceIds, resourceIndex, e);
                    listener.onFailure(
                        new OpenSearchStatusException("Failed to fetch resources: " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR)
                    );
                }
            }));
        }
    }

    /**
     * Updates resource sharing entries that match the specified source index and resource ID
     * using the provided update script. This method performs an update-by-query operation
     * in the resource sharing index.
     *
     * <p>The method executes the following steps:
     * <ol>
     *   <li>Creates a bool query to match exact source index and resource ID</li>
     *   <li>Constructs an update-by-query request with the query and update script</li>
     *   <li>Executes the update operation</li>
     *   <li>Returns success/failure status based on update results</li>
     * </ol>
     *
     * <p>Example document matching structure:
     * <pre>
     * {
     *   "source_idx": "source_index_name",
     *   "resource_id": "resource_id_value",
     *   "share_with": {
     *     // sharing configuration to be updated
     *   }
     * }
     * </pre>
     *
     * @param sourceIdx    The source index to match in the query (exact match)
     * @param resourceId   The resource ID to match in the query (exact match)
     * @param updateScript The script containing the update operations to be performed.
     *                     This script defines how the matching documents should be modified
     * @param listener     Listener to be notified when the operation completes
     * @apiNote This method:
     * <ul>
     *   <li>Uses term queries for exact matching of source_idx and resource_id</li>
     *   <li>Returns false for both "no matching documents" and "operation failure" cases</li>
     *   <li>Logs the complete update request for debugging purposes</li>
     *   <li>Provides detailed logging for success and failure scenarios</li>
     * </ul>
     * @implNote The update operation uses a bool query with two must clauses:
     * <pre>
     * {
     *   "query": {
     *     "bool": {
     *       "must": [
     *         { "term": { "source_idx.keyword": sourceIdx } },
     *         { "term": { "resource_id.keyword": resourceId } }
     *       ]
     *     }
     *   }
     * }
     * </pre>
     */
    private void updateByQueryResourceSharing(String sourceIdx, String resourceId, Script updateScript, ActionListener<Boolean> listener) {
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            BoolQueryBuilder query = QueryBuilders.boolQuery()
                .must(QueryBuilders.termQuery("source_idx.keyword", sourceIdx))
                .must(QueryBuilders.termQuery("resource_id.keyword", resourceId));

            UpdateByQueryRequest ubq = new UpdateByQueryRequest(resourceSharingIndex).setQuery(query)
                .setScript(updateScript)
                .setRefresh(true);

            client.execute(UpdateByQueryAction.INSTANCE, ubq, new ActionListener<>() {
                @Override
                public void onResponse(BulkByScrollResponse response) {
                    long updated = response.getUpdated();
                    if (updated > 0) {
                        LOGGER.debug("Successfully updated {} documents in {}.", updated, resourceSharingIndex);
                        listener.onResponse(true);
                    } else {
                        LOGGER.debug(
                            "No documents found to update in {} for source_idx: {} and resource_id: {}",
                            resourceSharingIndex,
                            sourceIdx,
                            resourceId
                        );
                        listener.onResponse(false);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    LOGGER.error("Failed to update documents in {}.", resourceSharingIndex, e);
                    listener.onFailure(e);

                }
            });
        } catch (Exception e) {
            LOGGER.error("Failed to update documents in {} before request submission.", resourceSharingIndex, e);
            listener.onFailure(e);
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

}
