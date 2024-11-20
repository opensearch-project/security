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

import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class ApiTokenAction extends BaseRestHandler {

    private ClusterService clusterService;
    private ThreadPool threadpool;
    private ApiTokenRepository apiTokenRepository;

    public static final String NAME_JSON_PROPERTY = "name";

    private static final List<RestHandler.Route> ROUTES = addRoutesPrefix(ImmutableList.of(new RestHandler.Route(POST, "/apitokens")));

    public ApiTokenAction(ClusterService clusterService, ThreadPool threadPool, Client client) {
        this.clusterService = clusterService;
        this.threadpool = threadPool;
        this.apiTokenRepository = new ApiTokenRepository(client, clusterService);
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
                String token = apiTokenRepository.createApiToken((String) requestBody.get(NAME_JSON_PROPERTY));

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
}
