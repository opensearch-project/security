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
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.logging.DeprecationLogger;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class ActionGroupsApiAction extends AbstractApiAction {

    private static final DeprecationLogger deprecationLogger = DeprecationLogger.getLogger(OpenSearchSecurityPlugin.class);

    static final String CLUSTER_TYPE = "cluster";

    static final String INDEX_TYPE = "index";

    static final Set<String> ALLOWED_TYPES = Set.of(CLUSTER_TYPE, INDEX_TYPE);

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            // legacy mapping for backwards compatibility
            // TODO: remove in next version
            new Route(Method.GET, "/actiongroup/{name}"),
            new Route(Method.GET, "/actiongroup"),
            new Route(Method.DELETE, "/actiongroup/{name}"),
            new Route(Method.PUT, "/actiongroup/{name}"),

            // corrected mapping, introduced in OpenSearch Security
            new Route(Method.GET, "/actiongroups/{name}"),
            new Route(Method.GET, "/actiongroups"),
            new Route(Method.DELETE, "/actiongroups/{name}"),
            new Route(Method.PUT, "/actiongroups/{name}"),
            new Route(Method.PATCH, "/actiongroups"),
            new Route(Method.PATCH, "/actiongroups/{name}")

        )
    );

    @Inject
    public ActionGroupsApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super(Endpoint.ACTIONGROUPS, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(this::actionGroupsApiRequestHandlers);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType getConfigType() {
        return CType.ACTIONGROUPS;
    }

    private void actionGroupsApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
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
            public ValidationResult<SecurityConfiguration> onConfigChange(SecurityConfiguration securityConfiguration) throws IOException {
                return EndpointValidator.super.onConfigChange(securityConfiguration).map(this::validateType)
                    .map(this::actionGroupNameIsNotSameAsRoleName)
                    .map(this::hasSelfReference);
            }

            @Override
            public ValidationResult<SecurityConfiguration> isAllowedToChangeImmutableEntity(SecurityConfiguration securityConfiguration)
                throws IOException {
                return EndpointValidator.super.isAllowedToChangeImmutableEntity(securityConfiguration).map(
                    this::isAllowedToChangeEntityWithRestAdminPermissions
                );
            }

            private ValidationResult<SecurityConfiguration> actionGroupNameIsNotSameAsRoleName(
                final SecurityConfiguration securityConfiguration
            ) throws IOException {
                // Prevent the case where action group and role share a same name.
                return loadConfiguration(CType.ROLES, false, false).map(
                    rolesConfiguration -> actionGroupNameIsNotSameAsRoleName(securityConfiguration, rolesConfiguration)
                );
            }

            private ValidationResult<SecurityConfiguration> actionGroupNameIsNotSameAsRoleName(
                final SecurityConfiguration securityConfiguration,
                final SecurityDynamicConfiguration<?> rolesConfiguration
            ) {
                if (rolesConfiguration.getCEntries().containsKey(securityConfiguration.entityName())) {
                    return ValidationResult.error(
                        RestStatus.BAD_REQUEST,
                        badRequestMessage(
                            securityConfiguration.entityName()
                                + " is an existing role. A action group cannot be named with an existing role name."
                        )
                    );
                }
                return ValidationResult.success(securityConfiguration);
            }

            private ValidationResult<SecurityConfiguration> validateType(final SecurityConfiguration securityConfiguration) {
                final var requestContent = securityConfiguration.requestContent();
                if (requestContent.has("type") && !ALLOWED_TYPES.contains(requestContent.get("type").asText().toLowerCase(Locale.ROOT))) {
                    final var supportedTypesMessage = String.format("Supported types are: %s, %s.", CLUSTER_TYPE, INDEX_TYPE);
                    return ValidationResult.error(
                        RestStatus.BAD_REQUEST,
                        badRequestMessage(
                            "Invalid action group type: " + requestContent.get("type").asText() + ". " + supportedTypesMessage
                        )

                    );
                }
                if (!requestContent.has("type")) {
                    deprecationLogger.deprecate(
                        "type",
                        "Possibility to creation or update of action groups without type is deprecated and will be removed in next major release."
                    );
                }
                return ValidationResult.success(securityConfiguration);
            }

            private ValidationResult<SecurityConfiguration> hasSelfReference(final SecurityConfiguration securityConfiguration)
                throws IOException {
                // Prevent the case where action group references to itself in the allowed_actions.
                final var actionGroups = (ActionGroupsV7) Utils.toConfigObject(
                    securityConfiguration.requestContent(),
                    securityConfiguration.configuration().getImplementingClass()
                );
                if (hasSelfReference(securityConfiguration.entityName(), actionGroups)) {
                    return ValidationResult.error(
                        RestStatus.BAD_REQUEST,
                        badRequestMessage(securityConfiguration.entityName() + " cannot be an allowed_action of itself")
                    );
                }
                return ValidationResult.success(securityConfiguration);
            }

            private boolean hasSelfReference(final String name, final ActionGroupsV7 actionGroups) {
                List<String> allowedActions = actionGroups.getAllowed_actions();
                return allowedActions.contains(name);
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
                        final ImmutableMap.Builder<String, DataType> allowedKeys = ImmutableMap.builder();
                        if (isCurrentUserAdmin()) {
                            allowedKeys.put("hidden", DataType.BOOLEAN);
                            allowedKeys.put("reserved", DataType.BOOLEAN);
                        }
                        allowedKeys.put("allowed_actions", DataType.ARRAY);
                        allowedKeys.put("description", DataType.STRING);
                        allowedKeys.put("type", DataType.STRING);
                        return allowedKeys.build();
                    }

                    @Override
                    public Set<String> mandatoryKeys() {
                        return ImmutableSet.of("allowed_actions");
                    }
                });
            }
        };
    }

}
