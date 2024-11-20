/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.action.apitokens;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.security.support.ConfigConstants;

public class ApiTokenIndexHandler {

    private Client client;
    private ClusterService clusterService;
    private static final Logger LOGGER = LogManager.getLogger(ApiTokenIndexHandler.class);

    public ApiTokenIndexHandler(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
    }

    public String indexToken(ApiToken token) {
        try (final ThreadContext.StoredContext ctx = client.threadPool().getThreadContext().stashContext()) {

            XContentBuilder builder = XContentFactory.jsonBuilder();
            String jsonString = token.toXContent(builder, ToXContent.EMPTY_PARAMS).toString();

            IndexRequest request = new IndexRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX).source(jsonString, XContentType.JSON);

            ActionListener<IndexResponse> irListener = ActionListener.wrap(idxResponse -> {
                LOGGER.info("Created {} entry.", ConfigConstants.OPENSEARCH_API_TOKENS_INDEX);
            }, (failResponse) -> {
                LOGGER.error(failResponse.getMessage());
                LOGGER.info("Failed to create {} entry.", ConfigConstants.OPENSEARCH_API_TOKENS_INDEX);
            });

            client.index(request, irListener);
            return token.getDescription();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    public void deleteToken(String name) throws ApiTokenException {
        try (final ThreadContext.StoredContext ctx = client.threadPool().getThreadContext().stashContext()) {
            DeleteByQueryRequest request = new DeleteByQueryRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX).setQuery(
                QueryBuilders.matchQuery("description", name)
            ).setRefresh(true);  // This will refresh the index after deletion

            BulkByScrollResponse response = client.execute(DeleteByQueryAction.INSTANCE, request).actionGet();

            long deletedDocs = response.getDeleted();

            if (deletedDocs == 0) {
                throw new ApiTokenException("No token found with name " + name);
            }
            LOGGER.info("Deleted " + deletedDocs + " documents");
        }
    }

    public List<Map<String, Object>> getApiTokens() {
        try (final ThreadContext.StoredContext ctx = client.threadPool().getThreadContext().stashContext()) {

            SearchRequest searchRequest = new SearchRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX);

            SearchResponse response = client.search(searchRequest).actionGet();

            List<Map<String, Object>> tokens = new ArrayList<>();
            for (SearchHit hit : response.getHits().getHits()) {
                tokens.add(hit.getSourceAsMap());
            }

            return tokens;
        }
    }

    public Boolean apiTokenIndexExists() {
        return clusterService.state().metadata().hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX);
    }

    public void createApiTokenIndexIfAbsent() {
        if (!apiTokenIndexExists()) {
            try (final ThreadContext.StoredContext ctx = client.threadPool().getThreadContext().stashContext()) {
                final Map<String, Object> indexSettings = ImmutableMap.of(
                    "index.number_of_shards",
                    1,
                    "index.auto_expand_replicas",
                    "0-all"
                );
                final CreateIndexRequest createIndexRequest = new CreateIndexRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX).settings(
                    indexSettings
                );
                LOGGER.info(client.admin().indices().create(createIndexRequest).actionGet().isAcknowledged());
            }
        }
    }

}
