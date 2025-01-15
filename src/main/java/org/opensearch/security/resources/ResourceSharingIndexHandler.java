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

import org.opensearch.OpenSearchException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.ClearScrollRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchScrollAction;
import org.opensearch.action.search.SearchScrollRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.MultiMatchQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
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
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.spi.resources.Resource;
import org.opensearch.security.spi.resources.ResourceAccessScope;
import org.opensearch.security.spi.resources.ResourceParser;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;

/**
 * This class handles the creation and management of the resource sharing index.
 * It provides methods to create the index, index resource sharing entries along with updates and deletion, retrieve shared resources.
 */
public class ResourceSharingIndexHandler {

    private static final Logger LOGGER = LogManager.getLogger(ResourceSharingIndexHandler.class);

    private final Client client;

    private final String resourceSharingIndex;

    private final ThreadPool threadPool;

    private final AuditLog auditLog;

    public ResourceSharingIndexHandler(final String indexName, final Client client, final ThreadPool threadPool, final AuditLog auditLog) {
        this.resourceSharingIndex = indexName;
        this.client = client;
        this.threadPool = threadPool;
        this.auditLog = auditLog;
    }

    public final static Map<String, Object> INDEX_SETTINGS = Map.of("index.number_of_shards", 1, "index.auto_expand_replicas", "0-all");

    /**
     * Creates the resource sharing index if it doesn't already exist.
     * This method initializes the index with predefined mappings and settings
     * for storing resource sharing information.
     * The index will be created with the following structure:
     * - source_idx (keyword): The source index containing the original document
     * - resource_id (keyword): The ID of the shared resource
     * - created_by (object): Information about the user who created the sharing
     *   - user (keyword): Username of the creator
     * - share_with (object): Access control configuration for shared resources
     *   - [group_name] (object): Name of the access group
     *     - users (array): List of users with access
     *     - roles (array): List of roles with access
     *     - backend_roles (array): List of backend roles with access
     *
     * @throws RuntimeException if there are issues reading/writing index settings
     *                    or communicating with the cluster
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
     * @param resourceId The unique identifier of the resource being shared
     * @param resourceIndex The source index where the original resource is stored
     * @param createdBy Object containing information about the user creating/updating the sharing
     * @param shareWith Object containing the sharing permissions' configuration. Can be null for initial creation.
     *                 When provided, it should contain the access control settings for different groups:
     *                 {
     *                     "group_name": {
     *                         "users": ["user1", "user2"],
     *                         "roles": ["role1", "role2"],
     *                         "backend_roles": ["backend_role1"]
     *                     }
     *                 }
     *
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

            ActionListener<IndexResponse> irListener = ActionListener.wrap(idxResponse -> {
                LOGGER.info("Successfully created {} entry.", resourceSharingIndex);
            }, (failResponse) -> {
                LOGGER.error(failResponse.getMessage());
                LOGGER.info("Failed to create {} entry.", resourceSharingIndex);
            });
            client.index(ir, irListener);
            return entry;
        } catch (Exception e) {
            LOGGER.info("Failed to create {} entry.", resourceSharingIndex, e);
            throw new OpenSearchException("Failed to create " + resourceSharingIndex + " entry.", e);
        }
    }

    /**
    * Fetches all resource sharing records that match the specified system index. This method retrieves
    * a list of resource IDs associated with the given system index from the resource sharing index.
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
    * @return Set<String> containing resource IDs that belong to the specified system index.
    *         Returns an empty list if:
    *         <ul>
    *           <li>No matching documents are found</li>
    *           <li>An error occurs during the search operation</li>
    *           <li>The system index parameter is invalid</li>
    *         </ul>
    *
    * @apiNote This method:
    * <ul>
    *   <li>Uses source filtering for optimal performance</li>
    *   <li>Performs exact matching on the source_idx field</li>
    *   <li>Returns an empty list instead of throwing exceptions</li>
    * </ul>
    */
    public Set<String> fetchAllDocuments(String pluginIndex) {
        LOGGER.debug("Fetching all documents from {} where source_idx = {}", resourceSharingIndex, pluginIndex);

        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            SearchRequest searchRequest = new SearchRequest(resourceSharingIndex);

            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(QueryBuilders.termQuery("source_idx.keyword", pluginIndex));
            searchSourceBuilder.size(10000); // TODO check what size should be set here.

            searchSourceBuilder.fetchSource(new String[] { "resource_id" }, null);

            searchRequest.source(searchSourceBuilder);

            SearchResponse searchResponse = client.search(searchRequest).actionGet();

            Set<String> resourceIds = new HashSet<>();

            SearchHit[] hits = searchResponse.getHits().getHits();
            for (SearchHit hit : hits) {
                Map<String, Object> sourceAsMap = hit.getSourceAsMap();
                if (sourceAsMap != null && sourceAsMap.containsKey("resource_id")) {
                    resourceIds.add(sourceAsMap.get("resource_id").toString());
                }
            }

            LOGGER.debug("Found {} documents in {} for source_idx: {}", resourceIds.size(), resourceSharingIndex, pluginIndex);

            return resourceIds;

        } catch (Exception e) {
            LOGGER.error("Failed to fetch documents from {} for source_idx: {}", resourceSharingIndex, pluginIndex, e);
            return Set.of();
        }
    }

    /**
    * Fetches documents that match the specified system index and have specific access type values.
    * This method uses scroll API to handle large result sets efficiently.
    *
    * <p>The method executes the following steps:
    * <ol>
    *   <li>Validates the RecipientType parameter</li>
    *   <li>Creates a scrolling search request with a compound query</li>
    *   <li>Processes results in batches using scroll API</li>
    *   <li>Collects all matching resource IDs</li>
    *   <li>Cleans up scroll context</li>
    * </ol>
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
    *                   "path": "share_with.*.RecipientType",
    *                   "query": {
    *                     "term": { "share_with.*.RecipientType": "entity_value" }
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
    * @param pluginIndex The source index to match against the source_idx field
    * @param entities Set of values to match in the specified RecipientType field
    * @param RecipientType The type of association with the resource. Must be one of:
    *                  <ul>
    *                    <li>"users" - for user-based access</li>
    *                    <li>"roles" - for role-based access</li>
    *                    <li>"backend_roles" - for backend role-based access</li>
    *                  </ul>
    * @return Set<String> List of resource IDs that match the criteria. The list may be empty
    *         if no matches are found
    *
    * @throws RuntimeException if the search operation fails
    *
    * @apiNote This method:
    * <ul>
    *   <li>Uses scroll API with 1-minute timeout</li>
    *   <li>Processes results in batches of 1000 documents</li>
    *   <li>Performs source filtering for optimization</li>
    *   <li>Uses nested queries for accessing array elements</li>
    *   <li>Properly cleans up scroll context after use</li>
    * </ul>
    */

    public Set<String> fetchDocumentsForAllScopes(String pluginIndex, Set<String> entities, String RecipientType) {
        // "*" must match all scopes
        return fetchDocumentsForAGivenScope(pluginIndex, entities, RecipientType, "*");
    }

    /**
     * Fetches documents that match the specified system index and have specific access type values for a given scope.
     * This method uses scroll API to handle large result sets efficiently.
     *
     * <p>The method executes the following steps:
     * <ol>
     *   <li>Validates the RecipientType parameter</li>
     *   <li>Creates a scrolling search request with a compound query</li>
     *   <li>Processes results in batches using scroll API</li>
     *   <li>Collects all matching resource IDs</li>
     *   <li>Cleans up scroll context</li>
     * </ol>
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
     *                   "path": "share_with.scope.RecipientType",
     *                   "query": {
     *                     "term": { "share_with.scope.RecipientType": "entity_value" }
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
     * @param pluginIndex The source index to match against the source_idx field
     * @param entities Set of values to match in the specified RecipientType field
     * @param RecipientType The type of association with the resource. Must be one of:
     *                  <ul>
     *                    <li>"users" - for user-based access</li>
     *                    <li>"roles" - for role-based access</li>
     *                    <li>"backend_roles" - for backend role-based access</li>
     *                  </ul>
     * @param scope The scope of the access. Should be implementation of {@link ResourceAccessScope}
     * @return Set<String> List of resource IDs that match the criteria. The list may be empty
     *         if no matches are found
     *
     * @throws RuntimeException if the search operation fails
     *
     * @apiNote This method:
     * <ul>
     *   <li>Uses scroll API with 1-minute timeout</li>
     *   <li>Processes results in batches of 1000 documents</li>
     *   <li>Performs source filtering for optimization</li>
     *   <li>Uses nested queries for accessing array elements</li>
     *   <li>Properly cleans up scroll context after use</li>
     * </ul>
     */
    public Set<String> fetchDocumentsForAGivenScope(String pluginIndex, Set<String> entities, String RecipientType, String scope) {
        LOGGER.debug(
            "Fetching documents from index: {}, where share_with.{}.{} contains any of {}",
            pluginIndex,
            scope,
            RecipientType,
            entities
        );

        Set<String> resourceIds = new HashSet<>();
        final Scroll scroll = new Scroll(TimeValue.timeValueMinutes(1L));

        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            SearchRequest searchRequest = new SearchRequest(resourceSharingIndex);
            searchRequest.scroll(scroll);

            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery().must(QueryBuilders.termQuery("source_idx.keyword", pluginIndex));

            BoolQueryBuilder shouldQuery = QueryBuilders.boolQuery();
            if ("*".equals(scope)) {
                for (String entity : entities) {
                    shouldQuery.should(
                        QueryBuilders.multiMatchQuery(entity, "share_with.*." + RecipientType + ".keyword")
                            .type(MultiMatchQueryBuilder.Type.BEST_FIELDS)
                    );
                }
            } else {
                for (String entity : entities) {
                    shouldQuery.should(QueryBuilders.termQuery("share_with." + scope + "." + RecipientType + ".keyword", entity));
                }
            }
            shouldQuery.minimumShouldMatch(1);

            boolQuery.must(QueryBuilders.existsQuery("share_with")).must(shouldQuery);

            executeSearchRequest(resourceIds, scroll, searchRequest, boolQuery);

            LOGGER.debug("Found {} documents matching the criteria in {}", resourceIds.size(), resourceSharingIndex);

            return resourceIds;

        } catch (Exception e) {
            LOGGER.error(
                "Failed to fetch documents from {} for criteria - pluginIndex: {}, scope: {}, RecipientType: {}, entities: {}",
                resourceSharingIndex,
                pluginIndex,
                scope,
                RecipientType,
                entities,
                e
            );
            throw new RuntimeException("Failed to fetch documents: " + e.getMessage(), e);
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
     * @param field The field name to search in. Must be a valid field in the index mapping
     * @param value The value to match for the specified field. Performs exact term matching
     * @return Set<String> List of resource IDs that match the criteria. Returns an empty list
     *         if no matches are found
     *
     * @throws IllegalArgumentException if any parameter is null or empty
     * @throws RuntimeException if the search operation fails, wrapping the underlying exception
     *
     * @apiNote This method:
     * <ul>
     *   <li>Uses scroll API with 1-minute timeout for handling large result sets</li>
     *   <li>Performs exact term matching (not analyzed) on field values</li>
     *   <li>Processes results in batches of 1000 documents</li>
     *   <li>Uses source filtering to only fetch resource_id field</li>
     *   <li>Automatically cleans up scroll context after use</li>
     * </ul>
     *
     * Example usage:
     * <pre>
     * Set<String> resources = fetchDocumentsByField("myIndex", "status", "active");
     * </pre>
     */
    public Set<String> fetchDocumentsByField(String pluginIndex, String field, String value) {
        if (StringUtils.isBlank(pluginIndex) || StringUtils.isBlank(field) || StringUtils.isBlank(value)) {
            throw new IllegalArgumentException("pluginIndex, field, and value must not be null or empty");
        }

        LOGGER.debug("Fetching documents from index: {}, where {} = {}", pluginIndex, field, value);

        Set<String> resourceIds = new HashSet<>();
        final Scroll scroll = new Scroll(TimeValue.timeValueMinutes(1L));

        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            SearchRequest searchRequest = new SearchRequest(resourceSharingIndex);
            searchRequest.scroll(scroll);

            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                .must(QueryBuilders.termQuery("source_idx.keyword", pluginIndex))
                .must(QueryBuilders.termQuery(field + ".keyword", value));

            executeSearchRequest(resourceIds, scroll, searchRequest, boolQuery);

            LOGGER.info("Found {} documents in {} where {} = {}", resourceIds.size(), resourceSharingIndex, field, value);

            return resourceIds;
        } catch (Exception e) {
            LOGGER.error("Failed to fetch documents from {} where {} = {}", resourceSharingIndex, field, value, e);
            throw new RuntimeException("Failed to fetch documents: " + e.getMessage(), e);
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
    * @param resourceId The resource ID to fetch. Must exactly match the resource_id field
    * @return ResourceSharing object if a matching document is found, null if no document
    *         matches the criteria
    *
    * @throws IllegalArgumentException if pluginIndexName or resourceId is null or empty
    * @throws RuntimeException if the search operation fails or parsing errors occur,
    *         wrapping the underlying exception
    *
    * @apiNote This method:
    * <ul>
    *   <li>Uses term queries for exact matching</li>
    *   <li>Expects only one matching document per resource ID</li>
    *   <li>Uses XContent parsing for consistent object creation</li>
    *   <li>Returns null instead of throwing exceptions for non-existent documents</li>
    *   <li>Provides detailed logging for troubleshooting</li>
    * </ul>
    *
    * Example usage:
    * <pre>
    * ResourceSharing sharing = fetchDocumentById("myIndex", "resource123");
    * if (sharing != null) {
    *     // Process the resource sharing object
    * }
    * </pre>
    */

    public ResourceSharing fetchDocumentById(String pluginIndex, String resourceId) {
        if (StringUtils.isBlank(pluginIndex) || StringUtils.isBlank(resourceId)) {
            throw new IllegalArgumentException("pluginIndexName and resourceId must not be null or empty");
        }

        LOGGER.debug("Fetching document from index: {}, with resourceId: {}", pluginIndex, resourceId);

        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            SearchRequest searchRequest = new SearchRequest(resourceSharingIndex);

            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                .must(QueryBuilders.termQuery("source_idx.keyword", pluginIndex))
                .must(QueryBuilders.termQuery("resource_id.keyword", resourceId));

            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(boolQuery).size(1); // We only need one document since
                                                                                                          // a resource must have only one
                                                                                                          // sharing entry
            searchRequest.source(searchSourceBuilder);

            SearchResponse searchResponse = client.search(searchRequest).actionGet();

            SearchHit[] hits = searchResponse.getHits().getHits();
            if (hits.length == 0) {
                LOGGER.debug("No document found for resourceId: {} in index: {}", resourceId, pluginIndex);
                return null;
            }

            SearchHit hit = hits[0];
            try (
                XContentParser parser = XContentType.JSON.xContent()
                    .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString())
            ) {

                parser.nextToken();

                ResourceSharing resourceSharing = ResourceSharing.fromXContent(parser);

                LOGGER.debug("Successfully fetched document for resourceId: {} from index: {}", resourceId, pluginIndex);

                return resourceSharing;
            }

        } catch (Exception e) {
            LOGGER.error("Failed to fetch document for resourceId: {} from index: {}", resourceId, pluginIndex, e);
            throw new OpenSearchException("Failed to fetch document for resourceId: " + resourceId + " from index: " + pluginIndex, e);
        }
    }

    /**
     * Helper method to execute a search request and collect resource IDs from the results.
     * @param resourceIds List to collect resource IDs
     * @param scroll Search Scroll
     * @param searchRequest Request to execute
     * @param boolQuery Query to execute with the request
     */
    private void executeSearchRequest(Set<String> resourceIds, Scroll scroll, SearchRequest searchRequest, BoolQueryBuilder boolQuery) {
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(boolQuery)
            .size(1000)
            .fetchSource(new String[] { "resource_id" }, null);

        searchRequest.source(searchSourceBuilder);

        SearchResponse searchResponse = client.search(searchRequest).actionGet();
        String scrollId = searchResponse.getScrollId();
        SearchHit[] hits = searchResponse.getHits().getHits();

        while (hits != null && hits.length > 0) {
            for (SearchHit hit : hits) {
                Map<String, Object> sourceAsMap = hit.getSourceAsMap();
                if (sourceAsMap != null && sourceAsMap.containsKey("resource_id")) {
                    resourceIds.add(sourceAsMap.get("resource_id").toString());
                }
            }

            SearchScrollRequest scrollRequest = new SearchScrollRequest(scrollId);
            scrollRequest.scroll(scroll);
            searchResponse = client.execute(SearchScrollAction.INSTANCE, scrollRequest).actionGet();
            scrollId = searchResponse.getScrollId();
            hits = searchResponse.getHits().getHits();
        }

        ClearScrollRequest clearScrollRequest = new ClearScrollRequest();
        clearScrollRequest.addScrollId(scrollId);
        client.clearScroll(clearScrollRequest).actionGet();
    }

    /**
     * Updates the sharing configuration for an existing resource in the resource sharing index.
     * NOTE: This method only grants new access. To remove access use {@link #revokeAccess(String, String, Map, Set, String, boolean)}
     * This method modifies the sharing permissions for a specific resource identified by its
     * resource ID and source index.
     *
     * @param resourceId The unique identifier of the resource whose sharing configuration needs to be updated
     * @param sourceIdx The source index where the original resource is stored
     * @param requestUserName The user requesting to share the resource
     * @param shareWith Updated sharing configuration object containing access control settings:
     *                 {
     *                     "scope": {
     *                         "users": ["user1", "user2"],
     *                         "roles": ["role1", "role2"],
     *                         "backend_roles": ["backend_role1"]
     *                     }
     *                 }
     * @param isAdmin Boolean indicating whether the user requesting to share is an admin or not
     * @return ResourceSharing Returns resourceSharing object if the update was successful, null otherwise
     * @throws RuntimeException if there's an error during the update operation
     */
    public ResourceSharing updateResourceSharingInfo(
        String resourceId,
        String sourceIdx,
        String requestUserName,
        ShareWith shareWith,
        boolean isAdmin
    ) {
        XContentBuilder builder;
        Map<String, Object> shareWithMap;
        try {
            builder = jsonBuilder();
            shareWith.toXContent(builder, ToXContent.EMPTY_PARAMS);
            String json = builder.toString();
            shareWithMap = DefaultObjectMapper.readValue(json, new TypeReference<>() {
            });

        } catch (IOException e) {
            LOGGER.error("Failed to build json content", e);
            throw new OpenSearchException("Failed to build json content", e);
        }

        // Check if the user requesting to share is the owner of the resource
        // TODO Add a way for users who are not creators to be able to share the resource
        ResourceSharing currentSharingInfo = fetchDocumentById(sourceIdx, resourceId);
        if (!isAdmin && currentSharingInfo != null && !currentSharingInfo.getCreatedBy().getCreator().equals(requestUserName)) {
            LOGGER.error("User {} is not authorized to share resource {}", requestUserName, resourceId);
            throw new OpenSearchException("User " + requestUserName + " is not authorized to share resource " + resourceId);
        }

        CreatedBy createdBy;
        if (currentSharingInfo == null) {
            createdBy = new CreatedBy(Creator.USER.getName(), requestUserName);
        } else {
            createdBy = currentSharingInfo.getCreatedBy();
        }

        // Atomic operation
        Script updateScript = new Script(ScriptType.INLINE, "painless", """
            if (ctx._source.share_with == null) {
                ctx._source.share_with = [:];
            }

            for (def entry : params.shareWith.entrySet()) {
                def scopeName = entry.getKey();
                def newScope = entry.getValue();

                if (!ctx._source.share_with.containsKey(scopeName)) {
                    def newScopeEntry = [:];
                    for (def field : newScope.entrySet()) {
                        if (field.getValue() != null && !field.getValue().isEmpty()) {
                            newScopeEntry[field.getKey()] = new HashSet(field.getValue());
                        }
                    }
                    ctx._source.share_with[scopeName] = newScopeEntry;
                } else {
                    def existingScope = ctx._source.share_with[scopeName];

                    for (def field : newScope.entrySet()) {
                        def fieldName = field.getKey();
                        def newValues = field.getValue();

                        if (newValues != null && !newValues.isEmpty()) {
                            if (!existingScope.containsKey(fieldName)) {
                                existingScope[fieldName] = new HashSet();
                            }

                            for (def value : newValues) {
                                if (!existingScope[fieldName].contains(value)) {
                                    existingScope[fieldName].add(value);
                                }
                            }
                        }
                    }
                }
            }
            """, Collections.singletonMap("shareWith", shareWithMap));

        boolean success = updateByQueryResourceSharing(sourceIdx, resourceId, updateScript);
        if (!success) {
            LOGGER.error("Failed to update resource sharing info for resource {}", resourceId);
            throw new OpenSearchException("Failed to update resource sharing info for resource " + resourceId);
        }

        return new ResourceSharing(resourceId, sourceIdx, createdBy, shareWith);
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
     * @param sourceIdx The source index to match in the query (exact match)
     * @param resourceId The resource ID to match in the query (exact match)
     * @param updateScript The script containing the update operations to be performed.
     *                    This script defines how the matching documents should be modified
     * @return boolean true if at least one document was updated, false if no documents
     *         were found or update failed
     *
     * @apiNote This method:
     * <ul>
     *   <li>Uses term queries for exact matching of source_idx and resource_id</li>
     *   <li>Returns false for both "no matching documents" and "operation failure" cases</li>
     *   <li>Logs the complete update request for debugging purposes</li>
     *   <li>Provides detailed logging for success and failure scenarios</li>
     * </ul>
     *
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
    private boolean updateByQueryResourceSharing(String sourceIdx, String resourceId, Script updateScript) {
        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            BoolQueryBuilder query = QueryBuilders.boolQuery()
                .must(QueryBuilders.termQuery("source_idx.keyword", sourceIdx))
                .must(QueryBuilders.termQuery("resource_id.keyword", resourceId));

            UpdateByQueryRequest ubq = new UpdateByQueryRequest(resourceSharingIndex).setQuery(query)
                .setScript(updateScript)
                .setRefresh(true);

            BulkByScrollResponse response = client.execute(UpdateByQueryAction.INSTANCE, ubq).actionGet();

            if (response.getUpdated() > 0) {
                LOGGER.info("Successfully updated {} documents in {}.", response.getUpdated(), resourceSharingIndex);
                return true;
            } else {
                LOGGER.info(
                    "No documents found to update in {} for source_idx: {} and resource_id: {}",
                    resourceSharingIndex,
                    sourceIdx,
                    resourceId
                );
                return false;
            }

        } catch (Exception e) {
            LOGGER.error("Failed to update documents in {}.", resourceSharingIndex, e);
            return false;
        }
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
     *     "scope": {
     *       "users": ["user1", "user2"],
     *       "roles": ["role1", "role2"],
     *       "backend_roles": ["backend_role1"]
     *     }
     *   }
     * }
     * </pre>
     *
     * @param resourceId The ID of the resource from which to revoke access
     * @param sourceIdx The name of the system index where the resource exists
     * @param revokeAccess A map containing entity types (USER, ROLE, BACKEND_ROLE) and their corresponding
     *                     values to be removed from the sharing configuration
     * @param scopes A list of scopes to revoke access from. If null or empty, access is revoked from all scopes
     * @param requestUserName The user trying to revoke the accesses
     * @param isAdmin Boolean indicating whether the user is an admin or not
     * @return The updated ResourceSharing object after revoking access, or null if the document doesn't exist
     * @throws IllegalArgumentException if resourceId, sourceIdx is null/empty, or if revokeAccess is null/empty
     * @throws RuntimeException if the update operation fails or encounters an error
     *
     * @see RecipientType
     * @see ResourceSharing
     *
     * @apiNote This method modifies the existing document. If no modifications are needed (i.e., specified
     *          entities don't exist in the current configuration), the original document is returned unchanged.
     * &#064;example
     * <pre>
     * Map<RecipientType, Set<String>> revokeAccess = new HashMap<>();
     * revokeAccess.put(RecipientType.USER, Set.of("user1", "user2"));
     * revokeAccess.put(RecipientType.ROLE, Set.of("role1"));
     * ResourceSharing updated = revokeAccess("resourceId", "pluginIndex", revokeAccess);
     * </pre>
     */
    public ResourceSharing revokeAccess(
        String resourceId,
        String sourceIdx,
        Map<RecipientType, Set<String>> revokeAccess,
        Set<String> scopes,
        String requestUserName,
        boolean isAdmin
    ) {
        if (StringUtils.isBlank(resourceId) || StringUtils.isBlank(sourceIdx) || revokeAccess == null || revokeAccess.isEmpty()) {
            throw new IllegalArgumentException("resourceId, sourceIdx, and revokeAccess must not be null or empty");
        }

        // TODO Check if access can be revoked by non-creator
        ResourceSharing currentSharingInfo = fetchDocumentById(sourceIdx, resourceId);
        if (!isAdmin && currentSharingInfo != null && !currentSharingInfo.getCreatedBy().getCreator().equals(requestUserName)) {
            LOGGER.error("User {} is not authorized to revoke access to resource {}", requestUserName, resourceId);
            throw new OpenSearchException("User " + requestUserName + " is not authorized to revoke access to resource " + resourceId);
        }

        LOGGER.debug("Revoking access for resource {} in {} for entities: {} and scopes: {}", resourceId, sourceIdx, revokeAccess, scopes);

        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            Map<String, Object> revoke = new HashMap<>();
            for (Map.Entry<RecipientType, Set<String>> entry : revokeAccess.entrySet()) {
                revoke.put(entry.getKey().getType().toLowerCase(), new ArrayList<>(entry.getValue()));
            }

            List<String> scopesToUse = scopes != null ? new ArrayList<>(scopes) : new ArrayList<>();

            Script revokeScript = new Script(ScriptType.INLINE, "painless", """
                if (ctx._source.share_with != null) {
                    Set scopesToProcess = new HashSet(params.scopes.isEmpty() ? ctx._source.share_with.keySet() : params.scopes);

                    for (def scopeName : scopesToProcess) {
                        if (ctx._source.share_with.containsKey(scopeName)) {
                            def existingScope = ctx._source.share_with.get(scopeName);

                            for (def entry : params.revokeAccess.entrySet()) {
                                def RecipientType = entry.getKey();
                                def entitiesToRemove = entry.getValue();

                                if (existingScope.containsKey(RecipientType) && existingScope[RecipientType] != null) {
                                    if (!(existingScope[RecipientType] instanceof HashSet)) {
                                        existingScope[RecipientType] = new HashSet(existingScope[RecipientType]);
                                    }

                                    existingScope[RecipientType].removeAll(entitiesToRemove);

                                    if (existingScope[RecipientType].isEmpty()) {
                                        existingScope.remove(RecipientType);
                                    }
                                }
                            }

                            if (existingScope.isEmpty()) {
                                ctx._source.share_with.remove(scopeName);
                            }
                        }
                    }
                }
                """, Map.of("revokeAccess", revoke, "scopes", scopesToUse));

            boolean success = updateByQueryResourceSharing(sourceIdx, resourceId, revokeScript);

            return success ? fetchDocumentById(sourceIdx, resourceId) : null;

        } catch (Exception e) {
            LOGGER.error("Failed to revoke access for resource: {} in index: {}", resourceId, sourceIdx, e);
            throw new RuntimeException("Failed to revoke access: " + e.getMessage(), e);
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
     * @param sourceIdx The source index to match in the query (exact match)
     * @param resourceId The resource ID to match in the query (exact match)
     * @return boolean true if at least one document was deleted, false if no documents were found or deletion failed
     *
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
    public boolean deleteResourceSharingRecord(String resourceId, String sourceIdx) {
        LOGGER.debug("Deleting documents from {} where source_idx = {} and resource_id = {}", resourceSharingIndex, sourceIdx, resourceId);

        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            DeleteByQueryRequest dbq = new DeleteByQueryRequest(resourceSharingIndex).setQuery(
                QueryBuilders.boolQuery()
                    .must(QueryBuilders.termQuery("source_idx.keyword", sourceIdx))
                    .must(QueryBuilders.termQuery("resource_id.keyword", resourceId))
            ).setRefresh(true);

            BulkByScrollResponse response = client.execute(DeleteByQueryAction.INSTANCE, dbq).actionGet();

            if (response.getDeleted() > 0) {
                LOGGER.info("Successfully deleted {} documents from {}", response.getDeleted(), resourceSharingIndex);
                return true;
            } else {
                LOGGER.info(
                    "No documents found to delete in {} for source_idx: {} and resource_id: {}",
                    resourceSharingIndex,
                    sourceIdx,
                    resourceId
                );
                return false;
            }

        } catch (Exception e) {
            LOGGER.error("Failed to delete documents from {}", resourceSharingIndex, e);
            return false;
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
    * @param name The username to match against the created_by.user field
    * @return boolean indicating whether the deletion was successful:
    *         <ul>
    *           <li>true - if one or more documents were deleted</li>
    *           <li>false - if no documents were found</li>
    *           <li>false - if the operation failed due to an error</li>
    *         </ul>
    *
    * @throws IllegalArgumentException if name is null or empty
    *
    *
    * @implNote Implementation details:
    * <ul>
    *   <li>Uses DeleteByQueryRequest for efficient bulk deletion</li>
    *   <li>Sets refresh=true for immediate consistency</li>
    *   <li>Uses term query for exact username matching</li>
    *   <li>Implements comprehensive error handling and logging</li>
    * </ul>
    *
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
    public boolean deleteAllRecordsForUser(String name) {
        if (StringUtils.isBlank(name)) {
            throw new IllegalArgumentException("Username must not be null or empty");
        }

        LOGGER.debug("Deleting all records for user {}", name);

        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            DeleteByQueryRequest deleteRequest = new DeleteByQueryRequest(resourceSharingIndex).setQuery(
                QueryBuilders.termQuery("created_by.user", name)
            ).setRefresh(true);

            BulkByScrollResponse response = client.execute(DeleteByQueryAction.INSTANCE, deleteRequest).actionGet();

            long deletedDocs = response.getDeleted();

            if (deletedDocs > 0) {
                LOGGER.info("Successfully deleted {} documents created by user {}", deletedDocs, name);
                return true;
            } else {
                LOGGER.info("No documents found for user {}", name);
                return false;
            }

        } catch (Exception e) {
            LOGGER.error("Failed to delete documents for user {}", name, e);
            return false;
        }
    }

    /**
     * Fetches all documents from the specified resource index and deserializes them into the specified class.
     *
     * @param resourceIndex The resource index to fetch documents from.
     * @param parser The class to deserialize the documents into a specified type defined by the parser.
     * @return A set of deserialized documents.
     */
    public <T extends Resource> Set<T> getResourceDocumentsFromIds(
        Set<String> resourceIds,
        String resourceIndex,
        ResourceParser<T> parser
    ) {
        Set<T> result = new HashSet<>();
        if (resourceIds.isEmpty()) {
            return result;
        }

        // stashing Context to avoid permission issues in-case resourceIndex is a system index
        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            MultiGetRequest request = new MultiGetRequest();
            for (String id : resourceIds) {
                request.add(new MultiGetRequest.Item(resourceIndex, id));
            }

            MultiGetResponse response = client.multiGet(request).actionGet();

            for (MultiGetItemResponse itemResponse : response.getResponses()) {
                if (!itemResponse.isFailed() && itemResponse.getResponse().isExists()) {
                    String sourceAsString = itemResponse.getResponse().getSourceAsString();
                    // T resource = DefaultObjectMapper.readValue(sourceAsString, clazz);
                    T resource = parser.parse(sourceAsString);
                    result.add(resource);
                }
            }
        } catch (IndexNotFoundException e) {
            LOGGER.error("Index {} does not exist", resourceIndex, e);
            throw e;
        } catch (Exception e) {
            LOGGER.error("Failed to fetch resources with ids {} from index {}", resourceIds, resourceIndex, e);
            throw new OpenSearchException("Failed to fetch resources: " + e.getMessage(), e);
        }

        return result;
    }
}
