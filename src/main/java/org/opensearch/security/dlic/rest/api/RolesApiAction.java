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

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.StreamSupport;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.fasterxml.jackson.core.JsonPointer;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.lang3.tuple.Pair;

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
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class RolesApiAction extends AbstractApiAction {

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new Route(Method.GET, "/roles"),
            new Route(Method.GET, "/roles/{name}"),
            new Route(Method.DELETE, "/roles/{name}"),
            new Route(Method.PUT, "/roles/{name}"),
            new Route(Method.PATCH, "/roles"),
            new Route(Method.PATCH, "/roles/{name}")
        )
    );

    public static class RoleRequestContentValidator extends RequestContentValidator {

        private static final Salt SALT = new Salt(new byte[] { 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6 });

        protected RoleRequestContentValidator(ValidationContext validationContext) {
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
            StreamSupport.stream(content.withArray(JsonPointer.compile("/index_permissions")).spliterator(), false)
                .flatMap(
                    indexPermissionsNode -> StreamSupport.stream(indexPermissionsNode.withArray("/masked_fields").spliterator(), false)
                )
                .map(this::validateMaskedFieldSyntax)
                .filter(Objects::nonNull)
                .forEach(wrongMaskedField -> {
                    this.validationError = ValidationError.WRONG_DATATYPE;
                    wrongDataTypes.put("Masked field not valid: " + wrongMaskedField.getLeft(), wrongMaskedField.getRight());
                });
            if (validationError != ValidationError.NONE) {
                return ValidationResult.error(RestStatus.BAD_REQUEST, this);
            }
            return ValidationResult.success(content);
        }

        private Pair<String, String> validateMaskedFieldSyntax(final JsonNode maskedFieldNode) {
            try {
                new MaskedField(
                    maskedFieldNode.asText(),
                    SALT,
                    validationContext.settings().get(ConfigConstants.SECURITY_MASKED_FIELDS_ALGORITHM_DEFAULT)
                ).isValid();
            } catch (Exception e) {
                return Pair.of(maskedFieldNode.asText(), e.getMessage());
            }
            return null;
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
                return EndpointValidator.super.isAllowedToChangeImmutableEntity(securityConfiguration).map(
                    ignore -> isAllowedToChangeEntityWithRestAdminPermissions(securityConfiguration)
                );
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return new RoleRequestContentValidator(new RequestContentValidator.ValidationContext() {
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
