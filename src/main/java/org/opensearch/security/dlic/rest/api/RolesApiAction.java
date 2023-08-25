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

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.ReadContext;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.configuration.MaskedField;
import org.opensearch.security.configuration.Salt;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class RolesApiAction extends AbstractApiAction {

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new Route(Method.GET, "/roles/"),
            new Route(Method.GET, "/roles/{name}"),
            new Route(Method.DELETE, "/roles/{name}"),
            new Route(Method.PUT, "/roles/{name}"),
            new Route(Method.PATCH, "/roles/"),
            new Route(Method.PATCH, "/roles/{name}")
        )
    );

    public static class RoleValidator extends RequestContentValidator {

        private static final Salt SALT = new Salt(new byte[] { 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6 });

        protected RoleValidator(ValidationContext validationContext) {
            super(validationContext);
        }

        @Override
        public ValidationResult<JsonNode> validate(RestRequest request) throws IOException {
            return super.validate(request).map(this::validateMaskedFields);
        }

        @Override
        public ValidationResult<JsonNode> validate(RestRequest request, JsonNode jsonContent) throws IOException {
            return super.validate(request, jsonContent).map(this::validateMaskedFields);
        }

        private ValidationResult<JsonNode> validateMaskedFields(final JsonNode content) {
            final ReadContext ctx = JsonPath.parse(content.toString());
            final List<String> maskedFields = ctx.read("$..masked_fields[*]");
            if (maskedFields != null) {
                for (String mf : maskedFields) {
                    if (!validateMaskedFieldSyntax(mf)) {
                        this.validationError = ValidationError.WRONG_DATATYPE;
                        return ValidationResult.error(RestStatus.BAD_REQUEST, this);
                    }
                }
            }
            return ValidationResult.success(content);
        }

        private boolean validateMaskedFieldSyntax(String mf) {
            try {
                new MaskedField(mf, SALT).isValid();
            } catch (Exception e) {
                wrongDataTypes.put("Masked field not valid: " + mf, e.getMessage());
                return false;
            }
            return true;
        }

    }

    @Inject
    public RolesApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super(Endpoint.ROLES, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(this::rolesApiRequestHandlers);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType getConfigType() {
        return CType.ROLES;
    }

    private void rolesApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.onChangeRequest(Method.PATCH, this::processPatchRequest).override(Method.POST, methodNotImplementedHandler);
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
            public ValidationResult<SecurityConfiguration> isAllowedToChangeImmutableEntity(SecurityConfiguration securityConfiguration)
                throws IOException {
                return EndpointValidator.super.isAllowedToChangeImmutableEntity(securityConfiguration).map(ignore -> {
                    if (isCurrentUserAdmin()) {
                        return ValidationResult.success(securityConfiguration);
                    }
                    return isAllowedToChangeEntityWithRestAdminPermissions(securityConfiguration);
                });
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return new RoleValidator(new RequestContentValidator.ValidationContext() {
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
                        if (isCurrentUserAdmin()) allowedKeys.put("reserved", DataType.BOOLEAN);
                        return allowedKeys.put("cluster_permissions", DataType.ARRAY)
                            .put("tenant_permissions", DataType.ARRAY)
                            .put("index_permissions", DataType.ARRAY)
                            .put("description", DataType.STRING)
                            .build();
                    }
                });
            }
        };
    }

}
