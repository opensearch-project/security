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

import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.rest.RestRequest.Method.*;
import static org.opensearch.security.dlic.rest.api.Responses.*;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class AuthFailureListenersApiAction extends AbstractApiAction {

    public static final String NAME_JSON_PROPERTY = "name";

    public static final String TYPE_JSON_PROPERTY = "type";
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

    protected AuthFailureListenersApiAction(
        ClusterService clusterService,
        ThreadPool threadPool,
        SecurityApiDependencies securityApiDependencies
    ) {
        super(Endpoint.AUTHFAILURELISTENERS, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(this::authFailureConfigApiRequestHandlers);
    }

    @Override
    public String getName() {
        return "Auth failure listener actions to Retrieve / Update configs.";
    }

    @Override
    public List<Route> routes() {
        return ROUTES;
    }

    @Override
    protected CType getConfigType() {
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
                        return ImmutableMap.of("test", DataType.OBJECT);
                    }
                });
            }
        };
    }

    private ToXContent authFailureContent(final ConfigV7 config) {
        return (builder, params) -> {
            builder.startObject();

            if (config.dynamic.auth_failure_listeners != null) {
                builder.startArray("auth_failure_listeners");

                for (String name : config.dynamic.auth_failure_listeners.getListeners().keySet()) {
                    ConfigV7.AuthFailureListener listener = config.dynamic.auth_failure_listeners.getListeners().get(name);
                    builder.startObject();
                    builder.field(NAME_JSON_PROPERTY, name);
                    builder.field(TYPE_JSON_PROPERTY, listener.type);
                    builder.field(AUTHENTICATION_BACKEND_JSON_PROPERTY, listener.authentication_backend);
                    builder.field(ALLOWED_TRIES_JSON_PROPERTY, listener.allowed_tries);
                    builder.field(TIME_WINDOW_SECONDS_JSON_PROPERTY, listener.time_window_seconds);
                    builder.field(BLOCK_EXPIRY_JSON_PROPERTY, listener.block_expiry_seconds);
                    builder.field(MAX_BLOCKED_CLIENTS_JSON_PROPERTY, listener.max_blocked_clients);
                    builder.field(MAX_TRACKED_CLIENTS_JSON_PROPERTY, listener.max_tracked_clients);
                    builder.endObject();
                }

                builder.endArray();
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

            String listenerName = request.param("name");
            if (listenerName == null) {
                badRequest(channel, "name is required");
            }

            // Try to remove the listener by name
            if (config.dynamic.auth_failure_listeners.getListeners().remove(listenerName) == null) {
                badRequest(channel, "listener not found");
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

                if (listenerName == null) {
                    badRequest(channel, "name is required");
                }
                ObjectNode test = (ObjectNode) DefaultObjectMapper.readTree(request.content().utf8ToString());
                SecurityJsonNode test2 = new SecurityJsonNode(test);

                // Try to remove the listener by name
                config.dynamic.auth_failure_listeners.getListeners()
                    .put(
                        listenerName,
                        new ConfigV7.AuthFailureListener(
                            test2.get(TYPE_JSON_PROPERTY).asString(),
                            test2.get(AUTHENTICATION_BACKEND_JSON_PROPERTY).asString(),
                            Integer.parseInt(test2.get(ALLOWED_TRIES_JSON_PROPERTY).asString()),
                            Integer.parseInt(test2.get(TIME_WINDOW_SECONDS_JSON_PROPERTY).asString()),
                            Integer.parseInt(test2.get(BLOCK_EXPIRY_JSON_PROPERTY).asString()),
                            Integer.parseInt(test2.get(MAX_BLOCKED_CLIENTS_JSON_PROPERTY).asString()),
                            Integer.parseInt(test2.get(MAX_TRACKED_CLIENTS_JSON_PROPERTY).asString())
                        )
                    );
                saveOrUpdateConfiguration(client, configuration, new OnSucessActionListener<>(channel) {
                    @Override
                    public void onResponse(IndexResponse indexResponse) {
                        ok(channel, authFailureContent(config));
                    }
                });
            }).error((status, toXContent) -> response(channel, status, toXContent)));

    }
}
