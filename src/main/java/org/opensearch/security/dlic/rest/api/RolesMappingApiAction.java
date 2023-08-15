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
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableList;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class RolesMappingApiAction extends PatchableResourceApiAction {

    protected final static String RESOURCE_NAME = "rolesmapping";

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new Route(Method.GET, "/rolesmapping/"),
            new Route(Method.GET, "/rolesmapping/{name}"),
            new Route(Method.DELETE, "/rolesmapping/{name}"),
            new Route(Method.PUT, "/rolesmapping/{name}"),
            new Route(Method.PATCH, "/rolesmapping/"),
            new Route(Method.PATCH, "/rolesmapping/{name}")
        )
    );

    @Inject
    public RolesMappingApiAction(
        final Settings settings,
        final Path configPath,
        final RestController controller,
        final Client client,
        final AdminDNs adminDNs,
        final ConfigurationRepository cl,
        final ClusterService cs,
        final PrincipalExtractor principalExtractor,
        final PrivilegesEvaluator evaluator,
        ThreadPool threadPool,
        AuditLog auditLog
    ) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
        this.requestHandlersBuilder.configureRequestHandlers(this::rolesMappingApiRequestHandlers);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.ROLESMAPPING;
    }

    @Override
    protected String getResourceName() {
        return RESOURCE_NAME;
    }

    @Override
    protected CType getConfigType() {
        return CType.ROLESMAPPING;
    }

    private void rolesMappingApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.override(Method.POST, methodNotImplementedHandler);
    }

    @Override
    protected boolean hasPermissionsToCreate(
        final SecurityDynamicConfiguration<?> dynamicConfigFactory,
        final Object content,
        final String resourceName
    ) throws IOException {
        final SecurityDynamicConfiguration<?> rolesConfiguration = load(CType.ROLES, false);
        if (restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(rolesConfiguration.getCEntry(resourceName))) {
            return isSuperAdmin();
        } else {
            return true;
        }
    }

    @Override
    protected boolean isReadOnly(SecurityDynamicConfiguration<?> existingConfiguration, String name) {
        final SecurityDynamicConfiguration<?> rolesConfiguration = load(CType.ROLES, false);
        if (restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(rolesConfiguration.getCEntry(name))) {
            return !isSuperAdmin();
        } else {
            return super.isReadOnly(existingConfiguration, name);
        }
    }

    @Override
    protected EndpointValidator createEndpointValidator() {
        return new EndpointValidator() {
            @Override
            public String resourceName() {
                return RESOURCE_NAME;
            }

            @Override
            public Endpoint endpoint() {
                return getEndpoint();
            }

            @Override
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return restApiAdminPrivilegesEvaluator;
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigChange(SecurityConfiguration securityConfiguration) throws IOException {
                return EndpointValidator.super.onConfigChange(securityConfiguration).map(this::validateRoleForMapping)
                    .map(this::canChangeObjectWithRestAdminPermissions);
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigDelete(SecurityConfiguration securityConfiguration) throws IOException {
                return EndpointValidator.super.onConfigDelete(securityConfiguration).map(this::canChangeObjectWithRestAdminPermissions);
            }

            private ValidationResult<SecurityConfiguration> validateRoleForMapping(final SecurityConfiguration securityConfiguration)
                throws IOException {
                return loadConfiguration(CType.ROLES, false, false).map(
                    rolesConfiguration -> validateRoles(List.of(securityConfiguration.entityName()), rolesConfiguration)
                ).map(ignore -> ValidationResult.success(securityConfiguration));
            }

            @Override
            public ValidationResult<SecurityConfiguration> hasRightsToChangeEntity(SecurityConfiguration securityConfiguration)
                throws IOException {
                return EndpointValidator.super.hasRightsToChangeEntity(securityConfiguration).map(
                    this::canChangeRoleMappingWithRestAdminPermissions
                );
            }

            public ValidationResult<SecurityConfiguration> canChangeRoleMappingWithRestAdminPermissions(
                SecurityConfiguration securityConfiguration
            ) throws IOException {
                return loadConfiguration(CType.ROLES, false, false).map(rolesConfiguration -> {
                    if (isCurrentUserAdmin()) {
                        return ValidationResult.success(securityConfiguration);
                    }
                    return canChangeObjectWithRestAdminPermissions(
                        SecurityConfiguration.of(securityConfiguration.entityName(), rolesConfiguration)
                    );
                }).map(ignore -> ValidationResult.success(securityConfiguration));
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
                        return settings;
                    }

                    @Override
                    public Set<String> mandatoryOrKeys() {
                        return ImmutableSet.of("backend_roles", "and_backend_roles", "hosts", "users");
                    }

                    @Override
                    public Map<String, DataType> allowedKeys() {
                        final ImmutableMap.Builder<String, DataType> allowedKeys = ImmutableMap.builder();
                        if (isCurrentUserAdmin()) allowedKeys.put("reserved", DataType.BOOLEAN);
                        return allowedKeys.put("backend_roles", DataType.ARRAY)
                            .put("and_backend_roles", DataType.ARRAY)
                            .put("hosts", DataType.ARRAY)
                            .put("users", DataType.ARRAY)
                            .put("description", DataType.STRING)
                            .build();
                    }
                });
            }
        };
    }

}
