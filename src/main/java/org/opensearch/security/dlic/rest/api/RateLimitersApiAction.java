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

package org.opensearch.security.dlic.rest.api;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.rest.RestRequest.Method.DELETE;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.PUT;
import static org.opensearch.security.dlic.rest.api.Responses.badRequest;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.notFound;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static org.opensearch.security.securityconf.impl.v7.ConfigV7.ALLOWED_TRIES_DEFAULT;
import static org.opensearch.security.securityconf.impl.v7.ConfigV7.BLOCK_EXPIRY_SECONDS_DEFAULT;
import static org.opensearch.security.securityconf.impl.v7.ConfigV7.MAX_BLOCKED_CLIENTS_DEFAULT;
import static org.opensearch.security.securityconf.impl.v7.ConfigV7.MAX_TRACKED_CLIENTS_DEFAULT;
import static org.opensearch.security.securityconf.impl.v7.ConfigV7.TIME_WINDOW_SECONDS_DEFAULT;

public class RateLimitersApiAction extends AbstractApiAction {

    public static final String IP_TYPE = "ip";

    public static final String USERNAME_TYPE = "username";

    public static final String NAME_JSON_PROPERTY = "name";

    public static final String TYPE_JSON_PROPERTY = "type";
    public static final String IGNORE_HOSTS_JSON_PROPERTY = "ignore_hosts";
    public static final String AUTHENTICATION_BACKEND_JSON_PROPERTY = "authentication_backend";
    public static final String ALLOWED_TRIES_JSON_PROPERTY = "allowed_tries";
    public static final String TIME_WINDOW_SECONDS_JSON_PROPERTY = "time_window_seconds";
    public static final String BLOCK_EXPIRY_JSON_PROPERTY = "block_expiry_seconds";
    public static final String MAX_BLOCKED_CLIENTS_JSON_PROPERTY = "max_blocked_clients";
    public static final String MAX_TRACKED_CLIENTS_JSON_PROPERTY = "max_tracked_clients";

    private static final List<Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(
            new Route(GET, "/authfailurelisteners"),
            new Route(DELETE, "/authfailurelisteners/{name}"),
            new Route(PUT, "/authfailurelisteners/{name}")
        )
    );

    protected RateLimitersApiAction(ClusterService clusterService, ThreadPool threadPool, SecurityApiDependencies securityApiDependencies) {
        super(Endpoint.RATELIMITERS, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(this::authFailureConfigApiRequestHandlers);
    }

    @Override
    public String getName() {
        return "Rate limiter actions to retrieve / update configs.";
    }

    @Override
    public List<Route> routes() {
        return ROUTES;
    }

    @Override
    protected CType<ConfigV7> getConfigType() {
        return CType.CONFIG;
    }

    @Override
    protected EndpointValidator createEndpointValidator() {
        return new EndpointValidator() {

            @Override
            public Endpoint endpoint() {
                return endpoint;
            }

            @Override
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return securityApiDependencies.restApiAdminPrivilegesEvaluator();
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
                    @Override
                    public Object[] params() {
                        return params;
                    }

                    @Override
                    public Settings settings() {
                        return securityApiDependencies.settings();
                    }

                    @Override
                    public Map<String, DataType> allowedKeys() {
                        final ImmutableMap.Builder<String, DataType> allowedKeys = ImmutableMap.builder();

                        return allowedKeys.put(TYPE_JSON_PROPERTY, DataType.STRING)
                            .put(IGNORE_HOSTS_JSON_PROPERTY, DataType.ARRAY)
                            .put(AUTHENTICATION_BACKEND_JSON_PROPERTY, DataType.STRING)
                            .put(ALLOWED_TRIES_JSON_PROPERTY, DataType.INTEGER)
                            .put(TIME_WINDOW_SECONDS_JSON_PROPERTY, DataType.INTEGER)
                            .put(BLOCK_EXPIRY_JSON_PROPERTY, DataType.INTEGER)
                            .put(MAX_BLOCKED_CLIENTS_JSON_PROPERTY, DataType.INTEGER)
                            .put(MAX_TRACKED_CLIENTS_JSON_PROPERTY, DataType.INTEGER)
                            .build();
                    }
                });
            }
        };
    }

    private ToXContent authFailureContent(final ConfigV7 config) {
        return (builder, params) -> {
            builder.startObject();
            for (String name : config.dynamic.auth_failure_listeners.getListeners().keySet()) {
                ConfigV7.AuthFailureListener listener = config.dynamic.auth_failure_listeners.getListeners().get(name);
                builder.startObject(name);
                builder.field(NAME_JSON_PROPERTY, name)
                    .field(TYPE_JSON_PROPERTY, listener.type)
                    .field(IGNORE_HOSTS_JSON_PROPERTY, listener.ignore_hosts)
                    .field(AUTHENTICATION_BACKEND_JSON_PROPERTY, listener.authentication_backend)
                    .field(ALLOWED_TRIES_JSON_PROPERTY, listener.allowed_tries)
                    .field(TIME_WINDOW_SECONDS_JSON_PROPERTY, listener.time_window_seconds)
                    .field(BLOCK_EXPIRY_JSON_PROPERTY, listener.block_expiry_seconds)
                    .field(MAX_BLOCKED_CLIENTS_JSON_PROPERTY, listener.max_blocked_clients)
                    .field(MAX_TRACKED_CLIENTS_JSON_PROPERTY, listener.max_tracked_clients);
                builder.endObject();
            }
            builder.endObject();
            return builder;
        };
    }

    private void authFailureConfigApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {

        requestHandlersBuilder.override(
            GET,
            (channel, request, client) -> loadConfiguration(getConfigType(), false, false).valid(configuration -> {
                final var config = (ConfigV7) configuration.getCEntry(CType.CONFIG.toLCString());
                ok(channel, authFailureContent(config));
            }).error((status, toXContent) -> response(channel, status, toXContent))
        ).override(DELETE, (channel, request, client) -> loadConfiguration(getConfigType(), false, false).valid(configuration -> {
            ConfigV7 config = (ConfigV7) configuration.getCEntry(CType.CONFIG.toLCString());

            String listenerName = request.param(NAME_JSON_PROPERTY);

            // Try to remove the listener by name
            if (config.dynamic.auth_failure_listeners.getListeners().remove(listenerName) == null) {
                notFound(channel, "listener not found");
            }
            saveOrUpdateConfiguration(client, configuration, new OnSucessActionListener<>(channel) {
                @Override
                public void onResponse(IndexResponse indexResponse) {
                    ok(channel, authFailureContent(config));
                }
            });
        }).error((status, toXContent) -> response(channel, status, toXContent)))
            .override(PUT, (channel, request, client) -> loadConfiguration(getConfigType(), false, false).valid(configuration -> {
                ConfigV7 config = (ConfigV7) configuration.getCEntry(CType.CONFIG.toLCString());

                String listenerName = request.param(NAME_JSON_PROPERTY);

                ObjectNode body = (ObjectNode) DefaultObjectMapper.readTree(request.content().utf8ToString());
                SecurityJsonNode authFailureListener = new SecurityJsonNode(body);
                ValidationResult<SecurityJsonNode> validationResult = validateAuthFailureListener(authFailureListener, listenerName);

                if (!validationResult.isValid()) {
                    badRequest(channel, validationResult.toString());
                    return;
                }

                // Try to put the listener by name
                config.dynamic.auth_failure_listeners.getListeners()
                    .put(listenerName, createAuthFailureListenerWithDefaults(authFailureListener));
                saveOrUpdateConfiguration(client, configuration, new OnSucessActionListener<>(channel) {
                    @Override
                    public void onResponse(IndexResponse indexResponse) {

                        ok(channel, authFailureContent(config));
                    }
                });
            }).error((status, toXContent) -> response(channel, status, toXContent)));

    }

    private ConfigV7.AuthFailureListener createAuthFailureListenerWithDefaults(SecurityJsonNode authFailureListener) {
        List<String> ignoreHosts = authFailureListener.get(IGNORE_HOSTS_JSON_PROPERTY).isNull()
            ? Collections.emptyList()
            : authFailureListener.get(IGNORE_HOSTS_JSON_PROPERTY).asList();

        return new ConfigV7.AuthFailureListener(
            authFailureListener.get(TYPE_JSON_PROPERTY).asString(),
            authFailureListener.get(AUTHENTICATION_BACKEND_JSON_PROPERTY).asString(),
            ignoreHosts,
            authFailureListener.get(ALLOWED_TRIES_JSON_PROPERTY).asInt(ALLOWED_TRIES_DEFAULT),
            authFailureListener.get(TIME_WINDOW_SECONDS_JSON_PROPERTY).asInt(TIME_WINDOW_SECONDS_DEFAULT),
            authFailureListener.get(BLOCK_EXPIRY_JSON_PROPERTY).asInt(BLOCK_EXPIRY_SECONDS_DEFAULT),
            authFailureListener.get(MAX_BLOCKED_CLIENTS_JSON_PROPERTY).asInt(MAX_BLOCKED_CLIENTS_DEFAULT),
            authFailureListener.get(MAX_TRACKED_CLIENTS_JSON_PROPERTY).asInt(MAX_TRACKED_CLIENTS_DEFAULT)
        );

    }

    private ValidationResult<SecurityJsonNode> validateAuthFailureListener(SecurityJsonNode authFailureListener, String name) {
        if (name == null) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("name is required"));
        }
        if (authFailureListener.get(TYPE_JSON_PROPERTY).isNull()) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("type is required"));
        }
        if (!(Set.of(IP_TYPE, USERNAME_TYPE).contains(authFailureListener.get(TYPE_JSON_PROPERTY).asString()))) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("type must be username or ip"));
        }
        if (authFailureListener.get(TYPE_JSON_PROPERTY).asString().equals(USERNAME_TYPE)
            && (authFailureListener.get(AUTHENTICATION_BACKEND_JSON_PROPERTY).isNull()
                || !authFailureListener.get(AUTHENTICATION_BACKEND_JSON_PROPERTY).asString().equals("internal"))) {
            return ValidationResult.error(
                RestStatus.BAD_REQUEST,
                badRequestMessage("username auth failure listeners must have 'internal' authentication backend")
            );
        }
        if (authFailureListener.get(TYPE_JSON_PROPERTY).asString().equals(IP_TYPE)
            && !authFailureListener.get(AUTHENTICATION_BACKEND_JSON_PROPERTY).isNull()) {
            return ValidationResult.error(
                RestStatus.BAD_REQUEST,
                badRequestMessage("ip auth failure listeners should not have an authentication backend")
            );
        }

        return ValidationResult.success(authFailureListener);
    }
}
