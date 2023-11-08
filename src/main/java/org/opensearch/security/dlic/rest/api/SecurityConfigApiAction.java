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

import com.google.common.collect.ImmutableMap;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.SECURITY_CONFIG_UPDATE;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;

public class SecurityConfigApiAction extends AbstractApiAction {

    private static final List<Route> routes = addRoutesPrefix(
        List.of(
            new Route(Method.GET, "/securityconfig"),
            new Route(Method.PATCH, "/securityconfig"),
            new Route(Method.PUT, "/securityconfig/config")
        )
    );

    private final boolean allowPutOrPatch;

    private final boolean restApiAdminEnabled;

    @Inject
    public SecurityConfigApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {

        super(Endpoint.CONFIG, clusterService, threadPool, securityApiDependencies);
        allowPutOrPatch = securityApiDependencies.settings()
            .getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, false);
        this.restApiAdminEnabled = securityApiDependencies.settings().getAsBoolean(SECURITY_RESTAPI_ADMIN_ENABLED, false);
        this.requestHandlersBuilder.configureRequestHandlers(this::securityConfigApiActionRequestHandlers);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType getConfigType() {
        return CType.CONFIG;
    }

    @Override
    protected void consumeParameters(RestRequest request) {}

    private void securityConfigApiActionRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.withAccessHandler(this::accessHandler)
            .verifyAccessForAllMethods()
            .onChangeRequest(Method.PUT, request -> processPutRequest("config", request))
            .onChangeRequest(Method.PATCH, this::processPatchRequest)
            .override(Method.DELETE, methodNotImplementedHandler)
            .override(Method.POST, methodNotImplementedHandler);
    }

    boolean accessHandler(final RestRequest request) {
        switch (request.method()) {
            case PATCH:
            case PUT:
                if (!restApiAdminEnabled) {
                    return allowPutOrPatch;
                } else {
                    return securityApiDependencies.restApiAdminPrivilegesEvaluator()
                        .isCurrentUserAdminFor(endpoint, SECURITY_CONFIG_UPDATE);
                }
            default:
                return true;
        }
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
                    public Map<String, RequestContentValidator.DataType> allowedKeys() {
                        return ImmutableMap.of("dynamic", DataType.OBJECT);
                    }
                });
            }
        };
    }

}
