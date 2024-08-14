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

import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.rest.RestRequest.Method.DELETE;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.security.dlic.rest.api.Responses.*;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class AuthFailureListenersApiAction extends AbstractApiAction {

    private static final List<Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(new Route(GET, "/authfailurelisteners"), new Route(DELETE, "/authfailurelisteners/{name}"))

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
                    builder.field("name", name);
                    builder.field("type", listener.type);
                    builder.field("authentication_backend", listener.authentication_backend);
                    builder.field("allowed_tries", listener.allowed_tries);
                    builder.field("time_window_seconds", listener.time_window_seconds);
                    builder.field("block_expiry_seconds", listener.block_expiry_seconds);
                    builder.field("max_blocked_clients", listener.max_blocked_clients);
                    builder.field("max_tracked_clients", listener.max_tracked_clients);
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
                return;
            }

            // Try to remove the listener by name
            if (config.dynamic.auth_failure_listeners.getListeners().remove(listenerName) == null) {
                badRequest(channel, "listener not found");
                return;
            }
            saveOrUpdateConfiguration(client, configuration, new OnSucessActionListener<>(channel) {
                @Override
                public void onResponse(IndexResponse indexResponse) {
                    ok(channel, authFailureContent(config));
                }
            });
        }).error((status, toXContent) -> response(channel, status, toXContent)));

    }
}
