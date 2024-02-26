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

import static org.opensearch.security.dlic.rest.api.AbstractApiAction.LOGGER;
import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;
import java.util.List;
import java.util.Map;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.dlic.rest.api.RolesApiAction.RoleRequestContentValidator;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigHelper;
import org.opensearch.threadpool.ThreadPool;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

public class ReservedRolesApiAction extends AbstractApiAction {

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new Route(Method.GET, "/roles/_reserved/_upgrade_check"),
            new Route(Method.POST, "/roles/_reserved/_upgrade_apply")
        )
    );

    @Inject
    public ReservedRolesApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super(Endpoint.ROLES, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(rhb -> {
            rhb.onGetRequest(request ->
                withIOException(() -> 
                    loadConfiguration(getConfigType(), false, false)
                    .map(securityConfiguration -> {
                        try {
                            final var entries = securityConfiguration.getCEntries();
                            final var entriesJson = convertJsonToJackson(entries);

                            Utils.
                        } catch (final Exception ex) {
                            // log it ?
                        }
                        return (JsonNode)null;
                    }))));
    }

    public static void uploadFile(
        String filepath,
        String index,
        CType cType,
    ) {
        final String configType = cType.toLCString();

        var fromDisk = AccessController.doPrivileged((PrivilegedExceptionAction<?>) () -> 
                ConfigHelper.fromYamlFile(filepath, cType, configVersion, 0, 0));
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
        requestHandlersBuilder.add(null, methodNotImplementedHandler).onChangeRequest(Method.POST, this::processUpgrade);
    }

    protected final ValidationResult<String> processUpgrade(final RestRequest request) throws IOException {
        return loadConfiguration(nameParam(request), false).map(
            securityConfiguration -> {
                final int existingRolesConfig = securityConfiguration.configuration().getCEntry(getConfigType());
                return ValidationResult.success("Upgrade Complete");
            }
        );
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
