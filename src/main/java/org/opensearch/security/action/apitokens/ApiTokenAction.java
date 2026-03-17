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
import java.util.List;

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
import org.opensearch.core.xcontent.XContentParser;
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
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.DELETE;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.action.apitokens.ApiToken.CLUSTER_PERMISSIONS_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.EXPIRATION_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.INDEX_PERMISSIONS_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.ISSUED_AT_FIELD;
import static org.opensearch.security.action.apitokens.ApiToken.NAME_FIELD;
import static org.opensearch.security.dlic.rest.api.Responses.forbidden;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;

public class ApiTokenAction extends BaseRestHandler {
    private final ApiTokenRepository apiTokenRepository;
    protected final Logger log = LogManager.getLogger(this.getClass());
    private final ThreadPool threadPool;
    private final ConfigurationRepository configurationRepository;
    private final PrivilegesConfiguration privilegesConfiguration;
    private final SecurityApiDependencies securityApiDependencies;
    private final ClusterService clusterService;
    private final IndexNameExpressionResolver indexNameExpressionResolver;

    private static final List<Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(new Route(POST, "/apitokens"), new Route(DELETE, "/apitokens/{id}"), new Route(GET, "/apitokens"))
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
        request.param(ApiToken.ID_FIELD);
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
                        builder.field(ApiToken.ID_FIELD, token.getId());
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
            }, exception -> sendErrorResponse(channel, RestStatus.INTERNAL_SERVER_ERROR, exception.getMessage())));
        };
    }

    private RestChannelConsumer handlePost(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                final ApiToken.CreateRequest createRequest;
                try (XContentParser parser = request.contentOrSourceParamParser()) {
                    createRequest = ApiToken.CreateRequest.fromXContent(parser);
                }

                apiTokenRepository.getTokenCount(ActionListener.wrap(tokenCount -> {
                    ConfigV7 config = configurationRepository.getConfiguration(CType.CONFIG).getCEntry(CType.CONFIG.name());
                    int maxTokens = config.dynamic.api_tokens.getMaxTokens();
                    if (tokenCount >= maxTokens) {
                        sendErrorResponse(
                            channel,
                            RestStatus.TOO_MANY_REQUESTS,
                            "Maximum limit of " + maxTokens + " API tokens reached. Please delete existing tokens before creating new ones."
                        );
                        return;
                    }
                    apiTokenRepository.createApiToken(
                        createRequest.getName(),
                        createRequest.getClusterPermissions(),
                        createRequest.getIndexPermissions(),
                        createRequest.getExpiration(),
                        wrapWithCacheRefresh(ActionListener.wrap(created -> {
                            apiTokenRepository.notifyAboutChanges();
                            XContentBuilder builder = channel.newBuilder();
                            builder.startObject().field(ApiToken.ID_FIELD, created.id()).field("token", created.token()).endObject();
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

    private RestChannelConsumer handleDelete(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                String id = request.param("id");
                apiTokenRepository.deleteApiToken(id, wrapWithCacheRefresh(ActionListener.wrap(ignored -> {
                    apiTokenRepository.notifyAboutChanges();
                    XContentBuilder builder = channel.newBuilder();
                    builder.startObject().field("message", "Token " + id + " deleted successfully.").endObject();
                    channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));
                },
                    deleteException -> sendErrorResponse(
                        channel,
                        RestStatus.INTERNAL_SERVER_ERROR,
                        "Failed to delete token: " + deleteException.getMessage()
                    )
                ), client));
            } catch (final Exception exception) {
                RestStatus status = exception instanceof ApiTokenException ? RestStatus.NOT_FOUND : RestStatus.INTERNAL_SERVER_ERROR;
                sendErrorResponse(channel, status, exception.getMessage());
            }
        };
    }

    private <T> ActionListener<T> wrapWithCacheRefresh(ActionListener<T> listener, NodeClient client) {
        return ActionListener.wrap(response -> {
            try {
                client.execute(
                    ApiTokenUpdateAction.INSTANCE,
                    new ApiTokenUpdateRequest(),
                    ActionListener.wrap(
                        updateResponse -> listener.onResponse(response),
                        exception -> listener.onFailure(new ApiTokenException("Failed to update API token", exception))
                    )
                );
            } catch (Exception e) {
                listener.onFailure(new ApiTokenException("Failed to update API token", e));
            }
        }, listener::onFailure);
    }

    private void sendErrorResponse(RestChannel channel, RestStatus status, String errorMessage) {
        try {
            XContentBuilder builder = channel.newBuilder();
            builder.startObject().field("error", errorMessage).endObject();
            channel.sendResponse(new BytesRestResponse(status, builder));
        } catch (Exception e) {
            log.error("Failed to send error response", e);
        }
    }

    protected String authorizeSecurityAccess(RestRequest request) throws IOException {
        if (!(securityApiDependencies.restApiAdminPrivilegesEvaluator().isCurrentUserAdminFor(Endpoint.APITOKENS)
            || securityApiDependencies.restApiPrivilegesEvaluator().checkAccessPermissions(request, Endpoint.APITOKENS) == null)) {
            return "User does not have required security API access";
        }
        return null;
    }
}
