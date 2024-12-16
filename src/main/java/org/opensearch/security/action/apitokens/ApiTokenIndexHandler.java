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
import java.util.HashMap;
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
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.support.ConfigConstants;

import static org.opensearch.security.action.apitokens.ApiToken.NAME_FIELD;

public class ApiTokenIndexHandler {

    private final Client client;
    private final ClusterService clusterService;
    private static final Logger LOGGER = LogManager.getLogger(ApiTokenIndexHandler.class);

    public ApiTokenIndexHandler(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
    }

    public String indexTokenMetadata(ApiToken token) {
        // TODO: move this out of index handler class, potentially create a layer in between baseresthandler and abstractapiaction which can
        // abstract this complexity away
        final var originalUserAndRemoteAddress = Utils.userAndRemoteAddressFrom(client.threadPool().getThreadContext());
        try (final ThreadContext.StoredContext ctx = client.threadPool().getThreadContext().stashContext()) {
            client.threadPool()
                .getThreadContext()
                .putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, originalUserAndRemoteAddress.getLeft());

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
            return token.getName();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    public void deleteToken(String name) throws ApiTokenException {
        final var originalUserAndRemoteAddress = Utils.userAndRemoteAddressFrom(client.threadPool().getThreadContext());
        try (final ThreadContext.StoredContext ctx = client.threadPool().getThreadContext().stashContext()) {
            client.threadPool()
                .getThreadContext()
                .putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, originalUserAndRemoteAddress.getLeft());
            DeleteByQueryRequest request = new DeleteByQueryRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX).setQuery(
                QueryBuilders.matchQuery(NAME_FIELD, name)
            ).setRefresh(true);

            BulkByScrollResponse response = client.execute(DeleteByQueryAction.INSTANCE, request).actionGet();

            long deletedDocs = response.getDeleted();

            if (deletedDocs == 0) {
                throw new ApiTokenException("No token found with name " + name);
            }
            LOGGER.info("Deleted " + deletedDocs + " documents");
        }
    }

    public Map<String, ApiToken> getTokenMetadatas() {
        final var originalUserAndRemoteAddress = Utils.userAndRemoteAddressFrom(client.threadPool().getThreadContext());
        try (final ThreadContext.StoredContext ctx = client.threadPool().getThreadContext().stashContext()) {
            client.threadPool()
                .getThreadContext()
                .putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, originalUserAndRemoteAddress.getLeft());
            SearchRequest searchRequest = new SearchRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX);
            searchRequest.source(new SearchSourceBuilder());

            SearchResponse response = client.search(searchRequest).actionGet();

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
                    tokens.put(token.getName(), token);
                }
            }
            return tokens;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public Boolean apiTokenIndexExists() {
        return clusterService.state().metadata().hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX);
    }

    public void createApiTokenIndexIfAbsent() {
        // TODO: Decide if this should be done at bootstrap
        if (!apiTokenIndexExists()) {
            final var originalUserAndRemoteAddress = Utils.userAndRemoteAddressFrom(client.threadPool().getThreadContext());
            try (final ThreadContext.StoredContext ctx = client.threadPool().getThreadContext().stashContext()) {
                client.threadPool()
                    .getThreadContext()
                    .putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, originalUserAndRemoteAddress.getLeft());
                final Map<String, Object> indexSettings = ImmutableMap.of(
                    "index.number_of_shards",
                    1,
                    "index.auto_expand_replicas",
                    "0-all"
                );
                final CreateIndexRequest createIndexRequest = new CreateIndexRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX).settings(
                    indexSettings
                );
                client.admin().indices().create(createIndexRequest);
            }
        }
    }

}
