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

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class AuthFailureListenersApiAction extends AbstractApiAction {

    private static final List<Route> ROUTES = addRoutesPrefix(
            ImmutableList.of(new Route(GET, "/authfailurelisteners"))

    );


    protected AuthFailureListenersApiAction(ClusterService clusterService, ThreadPool threadPool, SecurityApiDependencies securityApiDependencies) {
        super(Endpoint.AUTHFAILURELISTENERS, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(this::multiTenancyConfigApiRequestHandlers);
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
//                        return ImmutableMap.of(
//                                DEFAULT_TENANT_JSON_PROPERTY,
//                                DataType.STRING,
//                                PRIVATE_TENANT_ENABLED_JSON_PROPERTY,
//                                DataType.BOOLEAN,
//                                MULTITENANCY_ENABLED_JSON_PROPERTY,
//                                DataType.BOOLEAN,
//                                SIGN_IN_OPTIONS,
//                                DataType.ARRAY
//                        );
                        return ImmutableMap.of("test", DataType.OBJECT);
                    }
                });
            }
        };
    }

    private ToXContent multitenancyContent(final ConfigV7 config) {
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


    private void multiTenancyConfigApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.allMethodsNotImplemented()
                .override(GET, (channel, request, client) -> loadConfiguration(getConfigType(), false, false).valid(configuration -> {
                    final var config = (ConfigV7) configuration.getCEntry(CType.CONFIG.toLCString());
                    ok(channel, multitenancyContent(config));
                }).error((status, toXContent) -> response(channel, status, toXContent)));
    }
}
