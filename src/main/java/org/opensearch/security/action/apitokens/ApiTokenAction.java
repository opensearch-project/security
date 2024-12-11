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
import org.opensearch.security.securityconf.impl.v7.RoleV7;
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
                Map<String, ApiToken> tokens = apiTokenRepository.getApiTokens();

                builder.startArray();
                for (ApiToken token : tokens.values()) {
                    builder.startObject();
                    builder.field("name", token.getDescription());
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
        // TODO: Enforce unique token description
        return channel -> {
            final XContentBuilder builder = channel.newBuilder();
            BytesRestResponse response;
            try {
                final Map<String, Object> requestBody = request.contentOrSourceParamParser().map();

                validateRequestParametersForCreate(requestBody);
                List<String> clusterPermissions = extractClusterPermissions(requestBody);
                List<RoleV7.Index> indexPermissions = extractIndexPermissions(requestBody);

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

    /**
     * Validates the index permissions list structure
     */
    private void validateIndexPermissionsList(List<Map<String, Object>> indexPermsList) {
        for (Map<String, Object> indexPerm : indexPermsList) {
            // Validate index pattern
            if (!indexPerm.containsKey("index_pattern")) {
                throw new IllegalArgumentException("Each index permission must contain an index_pattern");
            }
            Object indexPatternObj = indexPerm.get("index_pattern");
            if (!(indexPatternObj instanceof String) && !(indexPatternObj instanceof List)) {
                throw new IllegalArgumentException("index_pattern must be a string or array of strings");
            }

            // Validate allowed actions
            if (!indexPerm.containsKey("allowed_actions")) {
                throw new IllegalArgumentException("Each index permission must contain allowed_actions");
            }
            if (!(indexPerm.get("allowed_actions") instanceof List)) {
                throw new IllegalArgumentException("allowed_actions must be an array");
            }

            // Validate DLS if present
            if (indexPerm.containsKey("dls") && !(indexPerm.get("dls") instanceof String)) {
                throw new IllegalArgumentException("dls must be a string");
            }

            // Validate FLS if present
            if (indexPerm.containsKey("fls") && !(indexPerm.get("fls") instanceof List)) {
                throw new IllegalArgumentException("fls must be an array");
            }

            // Validate masked fields if present
            if (indexPerm.containsKey("masked_fields") && !(indexPerm.get("masked_fields") instanceof List)) {
                throw new IllegalArgumentException("masked_fields must be an array");
            }
        }
    }

    private void validateRequestParametersForCreate(Map<String, Object> requestBody) {
        if (!requestBody.containsKey(NAME_JSON_PROPERTY)) {
            throw new IllegalArgumentException("Missing required parameter: " + NAME_JSON_PROPERTY);
        }

        // Validate cluster permissions if present
        if (requestBody.containsKey("cluster_permissions")) {
            Object permissions = requestBody.get("cluster_permissions");
            if (!(permissions instanceof List)) {
                throw new IllegalArgumentException("cluster_permissions must be an array");
            }
        }

        // Validate index permissions if present
        if (requestBody.containsKey("index_permissions")) {
            Object indexPerms = requestBody.get("index_permissions");
            if (!(indexPerms instanceof List)) {
                throw new IllegalArgumentException("index_permissions must be an array");
            }

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> indexPermsList = (List<Map<String, Object>>) indexPerms;
            validateIndexPermissionsList(indexPermsList);
        }
    }

    /**
     * Extracts cluster permissions from the request body
     */
    private List<String> extractClusterPermissions(Map<String, Object> requestBody) {
        if (!requestBody.containsKey("cluster_permissions")) {
            return Collections.emptyList();
        }

        @SuppressWarnings("unchecked")
        List<String> permissions = (List<String>) requestBody.get("cluster_permissions");
        return new ArrayList<>(permissions);
    }

    /**
     * Extracts and builds index permissions from the request body
     */
    private List<RoleV7.Index> extractIndexPermissions(Map<String, Object> requestBody) {
        if (!requestBody.containsKey("index_permissions")) {
            return Collections.emptyList();
        }

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> indexPerms = (List<Map<String, Object>>) requestBody.get("index_permissions");

        return indexPerms.stream().map(this::createIndexPermission).collect(Collectors.toList());
    }

    /**
     * Creates a single RoleV7.Index permission from a permission map
     */
    private RoleV7.Index createIndexPermission(Map<String, Object> indexPerm) {
        // Get index patterns (can be single string or list)
        List<String> indexPatterns;
        Object indexPatternObj = indexPerm.get("index_pattern");
        if (indexPatternObj instanceof String) {
            indexPatterns = Collections.singletonList((String) indexPatternObj);
        } else {
            @SuppressWarnings("unchecked")
            List<String> patterns = (List<String>) indexPatternObj;
            indexPatterns = patterns;
        }

        // Get allowed actions
        @SuppressWarnings("unchecked")
        List<String> allowedActions = (List<String>) indexPerm.get("allowed_actions");

        // Get DLS (Document Level Security)
        String dls = (String) indexPerm.getOrDefault("dls", "");

        // Get FLS (Field Level Security)
        @SuppressWarnings("unchecked")
        List<String> fls = indexPerm.containsKey("fls") ? (List<String>) indexPerm.get("fls") : Collections.emptyList();

        // Get masked fields
        @SuppressWarnings("unchecked")
        List<String> maskedFields = indexPerm.containsKey("masked_fields")
            ? (List<String>) indexPerm.get("masked_fields")
            : Collections.emptyList();

        return new RoleV7.Index(indexPatterns, allowedActions, dls, fls, maskedFields);
    }
}
