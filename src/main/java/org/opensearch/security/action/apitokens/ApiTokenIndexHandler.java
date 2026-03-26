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
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.transport.client.Client;

public class ApiTokenIndexHandler {

    private final Client client;
    private final ClusterService clusterService;
    private static final Logger LOGGER = LogManager.getLogger(ApiTokenIndexHandler.class);

    public ApiTokenIndexHandler(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
    }

    public void indexTokenMetadata(ApiToken token, ActionListener<String> listener) {
        try {
            XContentBuilder builder = XContentFactory.jsonBuilder();
            String jsonString = token.toXContent(builder, ToXContent.EMPTY_PARAMS).toString();

            IndexRequest request = new IndexRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX).source(jsonString, XContentType.JSON)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

            client.index(request, ActionListener.wrap(indexResponse -> {
                LOGGER.info("Created {} entry.", ConfigConstants.OPENSEARCH_API_TOKENS_INDEX);
                listener.onResponse(indexResponse.getId());
            }, exception -> {
                LOGGER.error(exception.getMessage());
                LOGGER.info("Failed to create {} entry.", ConfigConstants.OPENSEARCH_API_TOKENS_INDEX);
                listener.onFailure(exception);
            }));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void revokeToken(String id, ActionListener<Void> listener) {
        Map<String, Object> updateFields = Map.of(ApiToken.REVOKED_AT_FIELD, Instant.now().toEpochMilli());
        UpdateRequest request = new UpdateRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX, id).doc(updateFields)
            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        client.update(request, ActionListener.wrap(response -> {
            if (DocWriteResponse.Result.NOT_FOUND.equals(response.getResult())) {
                listener.onFailure(new ApiTokenException("No token found with id " + id));
            } else {
                listener.onResponse(null);
            }
        }, listener::onFailure));
    }

    public void getTokenMetadatas(ActionListener<Map<String, ApiToken>> listener) {
        try {
            SearchRequest searchRequest = new SearchRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX);
            searchRequest.source(new SearchSourceBuilder().size(10_000));

            client.search(searchRequest, ActionListener.wrap(response -> {
                try {
                    Map<String, ApiToken> tokens = new HashMap<>();
                    for (SearchHit hit : response.getHits().getHits()) {
                        try (
                            XContentParser parser = XContentType.JSON.xContent()
                                .createParser(
                                    NamedXContentRegistry.EMPTY,
                                    DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                                    hit.getSourceRef().streamInput()
                                )
                        ) {
                            ApiToken token = ApiToken.fromXContent(parser);
                            token.setId(hit.getId());
                            tokens.put(token.getTokenHash(), token);
                        }
                    }
                    listener.onResponse(tokens);
                } catch (IOException e) {
                    listener.onFailure(e);
                }
            }, listener::onFailure));
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    public Boolean apiTokenIndexExists() {
        return clusterService.state().metadata().hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX);
    }

    public void createApiTokenIndexIfAbsent(ActionListener<CreateIndexResponse> listener) {
        if (!apiTokenIndexExists()) {
            final Map<String, Object> indexSettings = ImmutableMap.of("index.number_of_shards", 1, "index.auto_expand_replicas", "0-all");
            final CreateIndexRequest createIndexRequest = new CreateIndexRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX).settings(
                indexSettings
            );
            client.admin().indices().create(createIndexRequest, listener);
        } else {
            listener.onResponse(null);
        }
    }

}
