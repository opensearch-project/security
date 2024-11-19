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
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class ApiTokenAction extends BaseRestHandler {

    private ClusterService clusterService;
    private ThreadPool threadpool;

    public static final String NAME_JSON_PROPERTY = "name";

    private static final List<RestHandler.Route> ROUTES = addRoutesPrefix(ImmutableList.of(new RestHandler.Route(POST, "/apitokens")));

    public ApiTokenAction(ClusterService clusterService, ThreadPool threadPool) {
        this.clusterService = clusterService;
        this.threadpool = threadPool;
    }

    @Override
    public String getName() {
        return "Actions to get and create API tokens.";
    }

    @Override
    public List<RestHandler.Route> routes() {
        return ROUTES;
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        switch (request.method()) {
            case POST:
                return handlePost(request, client);
            default:
                throw new IllegalArgumentException(request.method() + " not supported");
        }
    }

    private RestChannelConsumer handlePost(RestRequest request, NodeClient client) {
        return channel -> {
            final XContentBuilder builder = channel.newBuilder();
            BytesRestResponse response;
            try {
                final Map<String, Object> requestBody = request.contentOrSourceParamParser().map();

                validateRequestParameters(requestBody);
                String token = createApiToken((String) requestBody.get(NAME_JSON_PROPERTY), client);

                builder.startObject();
                builder.field("token", token);
                builder.endObject();

                response = new BytesRestResponse(RestStatus.OK, builder);
            } catch (final Exception exception) {
                builder.startObject().field("error", "An unexpected error occurred. Please check the input and try again.").endObject();
                response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
            }
            builder.close();
            channel.sendResponse(response);
        };

    }

    private void validateRequestParameters(Map<String, Object> requestBody) {
        if (!requestBody.containsKey(NAME_JSON_PROPERTY)) {
            throw new IllegalArgumentException("Name parameter is required and cannot be empty.");
        }
    }

    public String createApiToken(String name, Client client) {
        createApiTokenIndexIfAbsent(client);
        new ApiTokenIndexManager(client).indexToken(new ApiToken(name, "test-token", List.of()));
        return "test-token";
    }

    public Boolean apiTokenIndexExists() {
        return clusterService.state().metadata().hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX);
    }

    public void createApiTokenIndexIfAbsent(Client client) {
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
                logger.info(client.admin().indices().create(createIndexRequest).actionGet().isAcknowledged());
            }
        }
    }
}
