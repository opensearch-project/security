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

import static org.opensearch.rest.RestRequest.Method.DELETE;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class ApiTokenAction extends BaseRestHandler {
    private final ApiTokenRepository apiTokenRepository;

    public static final String NAME_JSON_PROPERTY = "name";

    private static final List<RestHandler.Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(
            new RestHandler.Route(POST, "/apitokens"),
            new RestHandler.Route(DELETE, "/apitokens"),
            new RestHandler.Route(GET, "/apitokens")
        )
    );

    public ApiTokenAction(ClusterService clusterService, ThreadPool threadPool, Client client) {
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
        // TODO: Authorize this API properly
        switch (request.method()) {
            case POST:
                return handlePost(request, client);
            case DELETE:
                return handleDelete(request, client);
            case GET:
                return handleGet(request, client);
            default:
                throw new IllegalArgumentException(request.method() + " not supported");
        }
    }

    private RestChannelConsumer handleGet(RestRequest request, NodeClient client) {
        return channel -> {
            final XContentBuilder builder = channel.newBuilder();
            BytesRestResponse response;
            try {
                List<Map<String, Object>> token = apiTokenRepository.getApiTokens();

                builder.startArray();
                for (int i = 0; i < token.toArray().length; i++) {
                    // TODO: refactor this to the helper function
                    builder.startObject();
                    builder.field("name", token.get(i).get("description"));
                    builder.field("creation_time", token.get(i).get("creation_time"));
                    builder.endObject();
                }
                builder.endArray();

                response = new BytesRestResponse(RestStatus.OK, builder);
            } catch (final Exception exception) {
                builder.startObject().field("error", "An unexpected error occurred. Please check the input and try again.").endObject();
                response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
            }
            builder.close();
            channel.sendResponse(response);
        };

    }

    private RestChannelConsumer handlePost(RestRequest request, NodeClient client) {
        // TODO: Enforce unique token description
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

    private RestChannelConsumer handleDelete(RestRequest request, NodeClient client) {
        return channel -> {
            final XContentBuilder builder = channel.newBuilder();
            BytesRestResponse response;
            try {
                final Map<String, Object> requestBody = request.contentOrSourceParamParser().map();

                validateRequestParameters(requestBody);
                apiTokenRepository.deleteApiToken((String) requestBody.get(NAME_JSON_PROPERTY));

                builder.startObject();
                builder.field("message", "token " + requestBody.get(NAME_JSON_PROPERTY) + " deleted successfully.");
                builder.endObject();

                response = new BytesRestResponse(RestStatus.OK, builder);
            } catch (final ApiTokenException exception) {
                builder.startObject().field("error", exception.getMessage()).endObject();
                response = new BytesRestResponse(RestStatus.NOT_FOUND, builder);
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
