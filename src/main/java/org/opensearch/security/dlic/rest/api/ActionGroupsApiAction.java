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
import com.google.common.collect.ImmutableSet;
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

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class ActionGroupsApiAction extends PatchableResourceApiAction {

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            // legacy mapping for backwards compatibility
            // TODO: remove in next version
            new Route(Method.GET, "/actiongroup/{name}"),
            new Route(Method.GET, "/actiongroup/"),
            new Route(Method.DELETE, "/actiongroup/{name}"),
            new Route(Method.PUT, "/actiongroup/{name}"),

            // corrected mapping, introduced in OpenSearch Security
            new Route(Method.GET, "/actiongroups/{name}"),
            new Route(Method.GET, "/actiongroups/"),
            new Route(Method.DELETE, "/actiongroups/{name}"),
            new Route(Method.PUT, "/actiongroups/{name}"),
            new Route(Method.PATCH, "/actiongroups/"),
            new Route(Method.PATCH, "/actiongroups/{name}")

        )
    );

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.ACTIONGROUPS;
    }

    @Inject
    public ActionGroupsApiAction(
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
    public List<Route> routes() {
        return routes;
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
            public Map<String, RequestContentValidator.DataType> allowedKeys() {
                final ImmutableMap.Builder<String, DataType> allowedKeys = ImmutableMap.builder();
                if (isSuperAdmin()) {
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

    @Override
    protected CType getConfigName() {
        return CType.ACTIONGROUPS;
    }

    @Override
    protected String getResourceName() {
        return "actiongroup";
    }

    @Override
    protected void consumeParameters(final RestRequest request) {
        request.param("name");
    }

    @Override
    protected void handlePut(RestChannel channel, RestRequest request, Client client, JsonNode content) throws IOException {
        final String name = request.param("name");

        if (name == null || name.length() == 0) {
            badRequestResponse(channel, "No " + getResourceName() + " specified.");
            return;
        }

        // Prevent the case where action group and role share a same name.
        SecurityDynamicConfiguration<?> existingRolesConfig = load(CType.ROLES, false);
        Set<String> existingRoles = existingRolesConfig.getCEntries().keySet();
        if (existingRoles.contains(name)) {
            badRequestResponse(channel, name + " is an existing role. A action group cannot be named with an existing role name.");
            return;
        }

        // Prevent the case where action group references to itself in the allowed_actions.
        final SecurityDynamicConfiguration<?> existingActionGroupsConfig = load(getConfigName(), false);
        final Object actionGroup = DefaultObjectMapper.readTree(content, existingActionGroupsConfig.getImplementingClass());
        existingActionGroupsConfig.putCObject(name, actionGroup);
        if (hasActionGroupSelfReference(existingActionGroupsConfig, name)) {
            badRequestResponse(channel, name + " cannot be an allowed_action of itself");
            return;
        }
        // prevent creation of groups for REST admin api
        if (restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(actionGroup)) {
            forbidden(channel, "Not allowed");
            return;
        }
        super.handlePut(channel, request, client, content);
    }

    @Override
    protected boolean hasPermissionsToCreate(
        final SecurityDynamicConfiguration<?> dynamicConfiguration,
        final Object content,
        final String resourceName
    ) throws IOException {
        if (restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(content)) {
            return false;
        }
        return true;
    }

    @Override
    protected boolean isReadOnly(SecurityDynamicConfiguration<?> existingConfiguration, String name) {
        if (restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(existingConfiguration.getCEntry(name))) {
            return true;
        }
        return super.isReadOnly(existingConfiguration, name);
    }
}
