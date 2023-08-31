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

import com.google.common.collect.ImmutableList;

import com.google.common.collect.ImmutableMap;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.methodNotImplementedMessage;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class SecurityConfigApiAction extends AbstractApiAction {

    private static final List<Route> getRoutes = addRoutesPrefix(Collections.singletonList(new Route(Method.GET, "/securityconfig/")));

    private static final List<Route> allRoutes = new ImmutableList.Builder<Route>().addAll(getRoutes)
        .addAll(
            addRoutesPrefix(ImmutableList.of(new Route(Method.PUT, "/securityconfig/{name}"), new Route(Method.PATCH, "/securityconfig/")))
        )
        .build();

    private final boolean allowPutOrPatch;

    @Inject
    public SecurityConfigApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {

        super(Endpoint.CONFIG, clusterService, threadPool, securityApiDependencies);
        allowPutOrPatch = securityApiDependencies.settings()
            .getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, false);
        this.requestHandlersBuilder.configureRequestHandlers(this::securityConfigApiActionRequestHandlers);
    }

    @Override
    public List<Route> routes() {
        return allowPutOrPatch ? allRoutes : getRoutes;
    }

    @Override
    protected CType getConfigType() {
        return CType.CONFIG;
    }

    private void securityConfigApiActionRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.onChangeRequest(
            Method.PUT,
            request -> withAllowedEndpoint(request).map(this::withConfigEntityNameOnly).map(ignore -> processPutRequest(request))
        )
            .onChangeRequest(Method.PATCH, request -> withAllowedEndpoint(request).map(this::processPatchRequest))
            .override(Method.DELETE, methodNotImplementedHandler)
            .override(Method.POST, methodNotImplementedHandler);
    }

    ValidationResult<RestRequest> withAllowedEndpoint(final RestRequest request) {
        if (!allowPutOrPatch) {
            return ValidationResult.error(RestStatus.NOT_IMPLEMENTED, methodNotImplementedMessage(request.method()));
        }
        return ValidationResult.success(request);
    }

    ValidationResult<String> withConfigEntityNameOnly(final RestRequest request) {
        final var name = nameParam(request);
        if (!"config".equals(name)) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("name must be config"));
        }
        return ValidationResult.success(name);
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
