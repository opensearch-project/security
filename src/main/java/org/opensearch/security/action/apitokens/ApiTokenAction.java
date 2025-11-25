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
import org.opensearch.security.privileges.PrivilegesConfiguration;
import org.opensearch.security.privileges.RoleMapper;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.DELETE;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.action.apitokens.ApiToken.ALLOWED_ACTIONS_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.ALLOWED_FIELDS;
import static org.opensearch.security.action.apitokens.ApiToken.CLUSTER_PERMISSIONS_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.EXPIRATION_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.INDEX_PATTERN_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.INDEX_PERMISSIONS_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.ISSUED_AT_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.NAME_FIELD;
import static org.opensearch.security.dlic.rest.api.Responses.forbidden;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.opensearch.security.util.ParsingUtils.safeMapList;
import static org.opensearch.security.util.ParsingUtils.safeStringList;

public class ApiTokenAction extends BaseRestHandler {
    private final ApiTokenRepository apiTokenRepository;
    public Logger log = LogManager.getLogger(this.getClass());
    private final ThreadPool threadPool;
    private final ConfigurationRepository configurationRepository;
    private final PrivilegesConfiguration privilegesConfiguration;
    private final SecurityApiDependencies securityApiDependencies;
    private final ClusterService clusterService;
    private final IndexNameExpressionResolver indexNameExpressionResolver;

    private static final List<Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(new Route(POST, "/apitokens"), new Route(DELETE, "/apitokens"), new Route(GET, "/apitokens"))
    );

    public ApiTokenAction(
        ThreadPool threadpool,
        ConfigurationRepository configurationRepository,
        PrivilegesConfiguration privilegesConfiguration,
        Settings settings,
        AdminDNs adminDns,
        AuditLog auditLog,
        Path configPath,
        PrincipalExtractor principalExtractor,
        ApiTokenRepository apiTokenRepository,
        ClusterService clusterService,
        IndexNameExpressionResolver indexNameExpressionResolver,
        RoleMapper roleMapper
    ) {
        this.apiTokenRepository = apiTokenRepository;
        this.threadPool = threadpool;
        this.configurationRepository = configurationRepository;
        this.privilegesConfiguration = privilegesConfiguration;
        this.securityApiDependencies = new SecurityApiDependencies(
            adminDns,
            configurationRepository,
            privilegesConfiguration,
            new RestApiPrivilegesEvaluator(settings, adminDns, roleMapper, principalExtractor, configPath, threadPool),
            new RestApiAdminPrivilegesEvaluator(
                threadPool.getThreadContext(),
                privilegesConfiguration,
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
        String authError = authorizeSecurityAccess(request);
        if (authError != null) {
            return channel -> forbidden(channel, "No permission to access REST API: " + authError);
        }
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
            apiTokenRepository.getApiTokens(ActionListener.wrap(tokens -> {
                try {
                    XContentBuilder builder = channel.newBuilder();
                    builder.startArray();
                    for (ApiToken token : tokens.values()) {
                        builder.startObject();
                        builder.field(NAME_FIELD, token.getName());
                        builder.field(ISSUED_AT_FIELD, token.getCreationTime().toEpochMilli());
                        builder.field(EXPIRATION_FIELD, token.getExpiration());
                        builder.field(CLUSTER_PERMISSIONS_FIELD, token.getClusterPermissions());
                        builder.field(INDEX_PERMISSIONS_FIELD, token.getIndexPermissions());
                        builder.endObject();
                    }
                    builder.endArray();

                    BytesRestResponse response = new BytesRestResponse(RestStatus.OK, builder);
                    builder.close();
                    channel.sendResponse(response);
                } catch (final Exception exception) {
                    sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, exception.getMessage());
                }
            }, exception -> {
                sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, exception.getMessage());

            }));

        };
    }

    private RestChannelConsumer handlePost(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                final Map<String, Object> requestBody = request.contentOrSourceParamParser().map();
                validateRequestParameters(requestBody);

                List<String> clusterPermissions = extractClusterPermissions(requestBody);
                List<ApiToken.IndexPermission> indexPermissions = extractIndexPermissions(requestBody);
                String name = (String) requestBody.get(NAME_FIELD);
                long expiration = (Long) requestBody.getOrDefault(
                    EXPIRATION_FIELD,
                    Instant.now().toEpochMilli() + TimeUnit.DAYS.toMillis(30)
                );

                // First check token count
                apiTokenRepository.getTokenCount(ActionListener.wrap(tokenCount -> {
                    if (tokenCount >= 100) {
                        sendErrorResponse(
                            channel,
                            RestStatus.TOO_MANY_REQUESTS,
                            "Maximum limit of 100 API tokens reached. Please delete existing tokens before creating new ones."
                        );
                        return;
                    }

                    apiTokenRepository.createApiToken(
                        name,
                        clusterPermissions,
                        indexPermissions,
                        expiration,
                        wrapWithCacheRefresh(ActionListener.wrap(token -> {
                            apiTokenRepository.notifyAboutChanges();
                            XContentBuilder builder = channel.newBuilder();
                            builder.startObject();
                            builder.field("token", token);
                            builder.endObject();
                            channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));
                            builder.close();

                        },
                            createException -> sendErrorResponse(
                                channel,
                                RestStatus.INTERNAL_SERVER_ERROR,
                                "Failed to create token: " + createException.getMessage()
                            )
                        ), client)
                    );
                },
                    countException -> sendErrorResponse(
                        channel,
                        RestStatus.INTERNAL_SERVER_ERROR,
                        "Failed to get token count: " + countException.getMessage()
                    )
                ));

            } catch (Exception e) {
                sendErrorResponse(channel, RestStatus.BAD_REQUEST, "Invalid request: " + e.getMessage());
            }
        };
    }

    private <T> ActionListener<T> wrapWithCacheRefresh(ActionListener<T> listener, NodeClient client) {
        return ActionListener.wrap(response -> {
            try {
                ApiTokenUpdateRequest updateRequest = new ApiTokenUpdateRequest();
                client.execute(
                    ApiTokenUpdateAction.INSTANCE,
                    updateRequest,
                    ActionListener.wrap(
                        updateResponse -> listener.onResponse(response),
                        exception -> listener.onFailure(new ApiTokenException("Failed to refresh cache", exception))
                    )
                );
            } catch (Exception e) {
                listener.onFailure(new ApiTokenException("Failed to refresh cache after operation", e));
            }
        }, listener::onFailure);
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
        // Check for unknown fields
        for (String field : requestBody.keySet()) {
            if (!ALLOWED_FIELDS.contains(field)) {
                throw new IllegalArgumentException("Unknown field in request: " + field);
            }
        }
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
                apiTokenRepository.deleteApiToken(
                    (String) requestBody.get(NAME_FIELD),
                    wrapWithCacheRefresh(ActionListener.wrap(ignored -> {
                        XContentBuilder builder = channel.newBuilder();
                        builder.startObject();
                        builder.field("message", "Token " + requestBody.get(NAME_FIELD) + " deleted successfully.");
                        builder.endObject();
                        channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));
                    },
                        deleteException -> sendErrorResponse(
                            channel,
                            RestStatus.INTERNAL_SERVER_ERROR,
                            "Failed to delete token: " + deleteException.getMessage()
                        )
                    ), client)
                );
            } catch (final Exception exception) {
                RestStatus status = RestStatus.INTERNAL_SERVER_ERROR;
                if (exception instanceof ApiTokenException) {
                    status = RestStatus.NOT_FOUND;
                }
                sendErrorResponse(channel, status, exception.getMessage());
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

    protected String authorizeSecurityAccess(RestRequest request) throws IOException {
        // Check if user has security API access
        if (!(securityApiDependencies.restApiAdminPrivilegesEvaluator().isCurrentUserAdminFor(Endpoint.APITOKENS)
            || securityApiDependencies.restApiPrivilegesEvaluator().checkAccessPermissions(request, Endpoint.APITOKENS) == null)) {
            return "User does not have required security API access";
        }
        return null;
    }
}
