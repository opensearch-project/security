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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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

    private static final String NAME_JSON_PROPERTY = "name";
    private static final String CLUSTER_PERMISSIONS_FIELD = "cluster_permissions";
    private static final String INDEX_PERMISSIONS_FIELD = "index_permissions";
    private static final String INDEX_PATTERN_FIELD = "index_pattern";
    private static final String ALLOWED_ACTIONS_FIELD = "allowed_actions";

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
                Map<String, ApiToken> tokens = apiTokenRepository.getApiTokens();

                builder.startArray();
                for (ApiToken token : tokens.values()) {
                    builder.startObject();
                    builder.field("name", token.getName());
                    builder.field("creation_time", token.getCreationTime().toEpochMilli());
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
        return channel -> {
            final XContentBuilder builder = channel.newBuilder();
            BytesRestResponse response;
            try {
                final Map<String, Object> requestBody = request.contentOrSourceParamParser().map();
                validateRequestParameters(requestBody);

                List<String> clusterPermissions = extractClusterPermissions(requestBody);
                List<ApiToken.IndexPermission> indexPermissions = extractIndexPermissions(requestBody);

                String token = apiTokenRepository.createApiToken(
                    (String) requestBody.get(NAME_JSON_PROPERTY),
                    clusterPermissions,
                    indexPermissions
                );

                builder.startObject();
                builder.field("token", token);
                builder.endObject();

                response = new BytesRestResponse(RestStatus.OK, builder);
            } catch (final Exception exception) {
                builder.startObject()
                    .field("error", "An unexpected error occurred. Please check the input and try again.")
                    .field("message", exception.getMessage())
                    .endObject();
                response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
            }
            builder.close();
            channel.sendResponse(response);
        };
    }

    /**
     * Safely casts an Object to List<String> with validation
     */
    List<String> safeStringList(Object obj, String fieldName) {
        if (!(obj instanceof List<?> list)) {
            throw new IllegalArgumentException(fieldName + " must be an array");
        }

        for (Object item : list) {
            if (!(item instanceof String)) {
                throw new IllegalArgumentException(fieldName + " must contain only strings");
            }
        }

        return list.stream().map(String.class::cast).collect(Collectors.toList());
    }

    /**
     * Safely casts an Object to List<Map<String, Object>> with validation
     */
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> safeMapList(Object obj, String fieldName) {
        if (!(obj instanceof List<?> list)) {
            throw new IllegalArgumentException(fieldName + " must be an array");
        }

        for (Object item : list) {
            if (!(item instanceof Map)) {
                throw new IllegalArgumentException(fieldName + " must contain object entries");
            }
        }
        return list.stream().map(item -> (Map<String, Object>) item).collect(Collectors.toList());
    }

    /**
     * Extracts cluster permissions from the request body
     */
    List<String> extractClusterPermissions(Map<String, Object> requestBody) {
        if (!requestBody.containsKey(CLUSTER_PERMISSIONS_FIELD)) {
            return Collections.emptyList();
        }

        return safeStringList(requestBody.get(CLUSTER_PERMISSIONS_FIELD), CLUSTER_PERMISSIONS_FIELD);
    }

    /**
     * Extracts and builds index permissions from the request body
     */
    List<ApiToken.IndexPermission> extractIndexPermissions(Map<String, Object> requestBody) {
        if (!requestBody.containsKey(INDEX_PERMISSIONS_FIELD)) {
            return Collections.emptyList();
        }

        List<Map<String, Object>> indexPerms = safeMapList(requestBody.get(INDEX_PERMISSIONS_FIELD), INDEX_PERMISSIONS_FIELD);

        return indexPerms.stream().map(this::createIndexPermission).collect(Collectors.toList());
    }

    /**
     * Creates a single RoleV7.Index permission from a permission map
     */
    ApiToken.IndexPermission createIndexPermission(Map<String, Object> indexPerm) {
        List<String> indexPatterns;
        Object indexPatternObj = indexPerm.get(INDEX_PATTERN_FIELD);
        if (indexPatternObj instanceof String) {
            indexPatterns = Collections.singletonList((String) indexPatternObj);
        } else {
            indexPatterns = safeStringList(indexPatternObj, INDEX_PATTERN_FIELD);
        }

        List<String> allowedActions = safeStringList(indexPerm.get(ALLOWED_ACTIONS_FIELD), ALLOWED_ACTIONS_FIELD);

        return new ApiToken.IndexPermission(indexPatterns, allowedActions);
    }

    /**
     * Validates the request parameters
     */
    void validateRequestParameters(Map<String, Object> requestBody) {
        if (!requestBody.containsKey(NAME_JSON_PROPERTY)) {
            throw new IllegalArgumentException("Missing required parameter: " + NAME_JSON_PROPERTY);
        }

        if (requestBody.containsKey(CLUSTER_PERMISSIONS_FIELD)) {
            Object permissions = requestBody.get(CLUSTER_PERMISSIONS_FIELD);
            if (!(permissions instanceof List)) {
                throw new IllegalArgumentException(CLUSTER_PERMISSIONS_FIELD + " must be an array");
            }
        }

        if (requestBody.containsKey(INDEX_PERMISSIONS_FIELD)) {
            List<Map<String, Object>> indexPermsList = safeMapList(requestBody.get(INDEX_PERMISSIONS_FIELD), INDEX_PERMISSIONS_FIELD);
            validateIndexPermissionsList(indexPermsList);
        }
    }

    /**
     * Validates the index permissions list structure
     */
    void validateIndexPermissionsList(List<Map<String, Object>> indexPermsList) {
        for (Map<String, Object> indexPerm : indexPermsList) {
            if (!indexPerm.containsKey(INDEX_PATTERN_FIELD)) {
                throw new IllegalArgumentException("Each index permission must contain " + INDEX_PATTERN_FIELD);
            }
            if (!indexPerm.containsKey(ALLOWED_ACTIONS_FIELD)) {
                throw new IllegalArgumentException("Each index permission must contain " + ALLOWED_ACTIONS_FIELD);
            }

            Object indexPatternObj = indexPerm.get(INDEX_PATTERN_FIELD);
            if (!(indexPatternObj instanceof String) && !(indexPatternObj instanceof List)) {
                throw new IllegalArgumentException(INDEX_PATTERN_FIELD + " must be a string or array of strings");
            }
        }
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

}
