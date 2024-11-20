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
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
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

    public Object getTokens() {
        try (final ThreadContext.StoredContext ctx = client.threadPool().getThreadContext().stashContext()) {

            return client.get(new GetRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX));

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
