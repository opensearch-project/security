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

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class RolesMappingApiAction extends PatchableResourceApiAction {
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
    }

    @Override
    protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content)
        throws IOException {
        final String name = request.param("name");

        if (name == null || name.length() == 0) {
            badRequestResponse(channel, "No " + getResourceName() + " specified.");
            return;
        }

        final SecurityDynamicConfiguration<?> rolesConfiguration = load(CType.ROLES, false);
        final SecurityDynamicConfiguration<?> rolesMappingConfiguration = load(getConfigName(), false);
        final boolean rolesMappingExists = rolesMappingConfiguration.exists(name);

        if (!isValidRolesMapping(channel, name)) return;

        if (restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(rolesConfiguration.getCEntry(name))) {
            if (!isSuperAdmin()) {
                forbidden(channel, "No permissions");
                return;
            }
        }
        rolesMappingConfiguration.putCObject(name, DefaultObjectMapper.readTree(content, rolesMappingConfiguration.getImplementingClass()));

        saveAndUpdateConfigs(
            this.securityIndexName,
            client,
            getConfigName(),
            rolesMappingConfiguration,
            new OnSucessActionListener<IndexResponse>(channel) {

                @Override
                public void onResponse(IndexResponse response) {
                    if (rolesMappingExists) {
                        successResponse(channel, "'" + name + "' updated.");
                    } else {
                        createdResponse(channel, "'" + name + "' created.");
                    }

                }
            }
        );
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
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.ROLESMAPPING;
    }

    @Override
    protected RequestContentValidator createValidator(final Object... params) {
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
                if (isSuperAdmin()) allowedKeys.put("reserved", DataType.BOOLEAN);
                return allowedKeys.put("backend_roles", DataType.ARRAY)
                    .put("and_backend_roles", DataType.ARRAY)
                    .put("hosts", DataType.ARRAY)
                    .put("users", DataType.ARRAY)
                    .put("description", DataType.STRING)
                    .build();
            }
        });
    }

    @Override
    protected String getResourceName() {
        return "rolesmapping";
    }

    @Override
    protected CType getConfigName() {
        return CType.ROLESMAPPING;
    }

}
