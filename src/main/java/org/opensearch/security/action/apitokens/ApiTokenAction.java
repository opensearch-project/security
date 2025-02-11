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
import java.nio.file.Path;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator;
import org.opensearch.security.dlic.rest.api.RestApiPrivilegesEvaluator;
import org.opensearch.security.dlic.rest.api.SecurityApiDependencies;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.rest.RestRequest.Method.DELETE;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.action.apitokens.ApiToken.ALLOWED_ACTIONS_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.CLUSTER_PERMISSIONS_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.CREATION_TIME_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.EXPIRATION_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.INDEX_PATTERN_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.INDEX_PERMISSIONS_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.NAME_FIELD;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.opensearch.security.util.ParsingUtils.safeMapList;
import static org.opensearch.security.util.ParsingUtils.safeStringList;

public class ApiTokenAction extends BaseRestHandler {
    private final ApiTokenRepository apiTokenRepository;
    public Logger log = LogManager.getLogger(this.getClass());
    private final ThreadPool threadPool;
    private final ConfigurationRepository configurationRepository;
    private final PrivilegesEvaluator privilegesEvaluator;
    private final SecurityApiDependencies securityApiDependencies;
    private final ClusterService clusterService;
    private final IndexNameExpressionResolver indexNameExpressionResolver;

    private static final List<Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(new Route(POST, "/apitokens"), new Route(DELETE, "/apitokens"), new Route(GET, "/apitokens"))
    );

    public ApiTokenAction(
        ThreadPool threadpool,
        ConfigurationRepository configurationRepository,
        PrivilegesEvaluator privilegesEvaluator,
        Settings settings,
        AdminDNs adminDns,
        AuditLog auditLog,
        Path configPath,
        PrincipalExtractor principalExtractor,
        ApiTokenRepository apiTokenRepository,
        ClusterService clusterService,
        IndexNameExpressionResolver indexNameExpressionResolver
    ) {
        this.apiTokenRepository = apiTokenRepository;
        this.threadPool = threadpool;
        this.configurationRepository = configurationRepository;
        this.privilegesEvaluator = privilegesEvaluator;
        this.securityApiDependencies = new SecurityApiDependencies(
            adminDns,
            configurationRepository,
            privilegesEvaluator,
            new RestApiPrivilegesEvaluator(settings, adminDns, privilegesEvaluator, principalExtractor, configPath, threadPool),
            new RestApiAdminPrivilegesEvaluator(
                threadPool.getThreadContext(),
                privilegesEvaluator,
                adminDns,
                settings.getAsBoolean(SECURITY_RESTAPI_ADMIN_ENABLED, false)
            ),
            auditLog,
            settings
        );
        this.clusterService = clusterService;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
    }

    @Override
    public String getName() {
        return "api_token_action";
    }

    @Override
    public List<Route> routes() {
        return ROUTES;
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        authorizeSecurityAccess(request);
        return doPrepareRequest(request, client);
    }

    RestChannelConsumer doPrepareRequest(RestRequest request, NodeClient client) {
        final var originalUserAndRemoteAddress = Utils.userAndRemoteAddressFrom(client.threadPool().getThreadContext());
        try (final ThreadContext.StoredContext ctx = client.threadPool().getThreadContext().stashContext()) {
            client.threadPool()
                .getThreadContext()
                .putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, originalUserAndRemoteAddress.getLeft());
            return switch (request.method()) {
                case POST -> handlePost(request, client);
                case DELETE -> handleDelete(request, client);
                case GET -> handleGet(request, client);
                default -> throw new IllegalArgumentException(request.method() + " not supported");
            };
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
                    builder.field(NAME_FIELD, token.getName());
                    builder.field(CREATION_TIME_FIELD, token.getCreationTime().toEpochMilli());
                    builder.field(EXPIRATION_FIELD, token.getExpiration());
                    builder.field(CLUSTER_PERMISSIONS_FIELD, token.getClusterPermissions());
                    builder.field(INDEX_PERMISSIONS_FIELD, token.getIndexPermissions());
                    builder.endObject();
                }
                builder.endArray();

                response = new BytesRestResponse(RestStatus.OK, builder);
            } catch (final Exception exception) {
                builder.startObject().field("error", exception.getMessage()).endObject();
                response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
            }
            builder.close();
            channel.sendResponse(response);
        };
    }

    private RestChannelConsumer handlePost(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                final Map<String, Object> requestBody = request.contentOrSourceParamParser().map();
                validateRequestParameters(requestBody);

                List<String> clusterPermissions = extractClusterPermissions(requestBody);
                List<ApiToken.IndexPermission> indexPermissions = extractIndexPermissions(requestBody);

                String token = apiTokenRepository.createApiToken(
                    (String) requestBody.get(NAME_FIELD),
                    clusterPermissions,
                    indexPermissions,
                    (Long) requestBody.getOrDefault(EXPIRATION_FIELD, Instant.now().toEpochMilli() + TimeUnit.DAYS.toMillis(30))
                );

                // Then trigger the update action
                ApiTokenUpdateRequest updateRequest = new ApiTokenUpdateRequest();
                client.execute(ApiTokenUpdateAction.INSTANCE, updateRequest, new ActionListener<ApiTokenUpdateResponse>() {
                    @Override
                    public void onResponse(ApiTokenUpdateResponse updateResponse) {
                        try {
                            XContentBuilder builder = channel.newBuilder();
                            builder.startObject();
                            builder.field("Api Token: ", token);
                            builder.endObject();

                            BytesRestResponse response = new BytesRestResponse(RestStatus.OK, builder);
                            channel.sendResponse(response);
                        } catch (IOException e) {
                            sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, "Failed to send response after token creation");
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, "Failed to propagate token creation");
                    }
                });
            } catch (final Exception exception) {
                sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, exception.getMessage());
            }
        };
    }

    /**
     * Extracts cluster permissions from the request body
     */
    List<String> extractClusterPermissions(Map<String, Object> requestBody) {
        return safeStringList(requestBody.get(CLUSTER_PERMISSIONS_FIELD), CLUSTER_PERMISSIONS_FIELD);
    }

    /**
     * Extracts and builds index permissions from the request body
     */
    List<ApiToken.IndexPermission> extractIndexPermissions(Map<String, Object> requestBody) {
        List<Map<String, Object>> indexPerms = safeMapList(requestBody.get(INDEX_PERMISSIONS_FIELD), INDEX_PERMISSIONS_FIELD);
        return indexPerms.stream().map(this::createIndexPermission).collect(Collectors.toList());
    }

    /**
     * Creates a single index permission from a permission map
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
        if (!requestBody.containsKey(NAME_FIELD)) {
            throw new IllegalArgumentException("Missing required parameter: " + NAME_FIELD);
        }

        if (requestBody.containsKey(EXPIRATION_FIELD)) {
            Object expiration = requestBody.get(EXPIRATION_FIELD);
            if (!(expiration instanceof Long)) {
                throw new IllegalArgumentException(EXPIRATION_FIELD + " must be a long");
            }
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
            try {
                final Map<String, Object> requestBody = request.contentOrSourceParamParser().map();

                validateRequestParameters(requestBody);
                apiTokenRepository.deleteApiToken((String) requestBody.get(NAME_FIELD));

                ApiTokenUpdateRequest updateRequest = new ApiTokenUpdateRequest();
                client.execute(ApiTokenUpdateAction.INSTANCE, updateRequest, new ActionListener<ApiTokenUpdateResponse>() {
                    @Override
                    public void onResponse(ApiTokenUpdateResponse updateResponse) {
                        try {
                            XContentBuilder builder = channel.newBuilder();
                            builder.startObject();
                            builder.field("message", "token " + requestBody.get(NAME_FIELD) + " deleted successfully.");
                            builder.endObject();

                            BytesRestResponse response = new BytesRestResponse(RestStatus.OK, builder);
                            channel.sendResponse(response);
                        } catch (Exception e) {
                            sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, "Failed to send response after token update");
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, "Failed to propagate token deletion");
                    }
                });
            } catch (final ApiTokenException exception) {
                sendErrorResponse(channel, RestStatus.NOT_FOUND, exception.getMessage());
            } catch (final Exception exception) {
                sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, exception.getMessage());
            }
        };

    }

    private void sendErrorResponse(RestChannel channel, RestStatus status, String errorMessage) {
        try {
            XContentBuilder builder = channel.newBuilder();
            builder.startObject().field("error", errorMessage).endObject();
            BytesRestResponse response = new BytesRestResponse(status, builder);
            channel.sendResponse(response);
        } catch (Exception e) {
            log.error("Failed to send error response", e);
        }
    }

    protected void authorizeSecurityAccess(RestRequest request) throws IOException {
        // Check if user has security API access
        if (!(securityApiDependencies.restApiAdminPrivilegesEvaluator().isCurrentUserAdminFor(Endpoint.APITOKENS)
            || securityApiDependencies.restApiPrivilegesEvaluator().checkAccessPermissions(request, Endpoint.APITOKENS) == null)) {
            throw new SecurityException("User does not have required security API access");
        }
    }
}
