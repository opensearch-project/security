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
import java.util.Collections;
import java.util.List;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.inject.Inject;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.Migration;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v6.ActionGroupsV6;
import org.opensearch.security.securityconf.impl.v6.ConfigV6;
import org.opensearch.security.securityconf.impl.v6.InternalUserV6;
import org.opensearch.security.securityconf.impl.v6.RoleMappingsV6;
import org.opensearch.security.securityconf.impl.v6.RoleV6;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.securityconf.impl.v7.InternalUserV7;
import org.opensearch.security.securityconf.impl.v7.RoleMappingsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.securityconf.impl.v7.TenantV7;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.Responses.badRequest;
import static org.opensearch.security.dlic.rest.api.Responses.internalServerError;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class ValidateApiAction extends AbstractApiAction {
    private static final List<Route> routes = addRoutesPrefix(Collections.singletonList(new Route(Method.GET, "/validate")));

    @Inject
    public ValidateApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super(Endpoint.VALIDATE, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(this::validateApiRequestHandlers);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType getConfigType() {
        return null;
    }

    @Override
    protected void consumeParameters(final RestRequest request) {
        request.paramAsBoolean("accept_invalid", false);
    }

    private void validateApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.allMethodsNotImplemented().override(Method.GET, (channel, request, client) -> validate(channel, request));
    }

    @SuppressWarnings("unchecked")
    protected void validate(RestChannel channel, RestRequest request) throws IOException {

        final boolean acceptInvalid = request.paramAsBoolean("accept_invalid", false);

        final SecurityDynamicConfiguration<?> loadedConfig = load(CType.CONFIG, true, acceptInvalid);

        if (loadedConfig.getVersion() != 1) {
            badRequest(channel, "Can not migrate configuration because it was already migrated.");
            return;
        }

        try {
            final SecurityDynamicConfiguration<ConfigV6> configV6 = (SecurityDynamicConfiguration<ConfigV6>) loadedConfig;
            final SecurityDynamicConfiguration<ActionGroupsV6> actionGroupsV6 = (SecurityDynamicConfiguration<ActionGroupsV6>) load(
                CType.ACTIONGROUPS,
                true,
                acceptInvalid
            );
            final SecurityDynamicConfiguration<InternalUserV6> internalUsersV6 = (SecurityDynamicConfiguration<InternalUserV6>) load(
                CType.INTERNALUSERS,
                true,
                acceptInvalid
            );
            final SecurityDynamicConfiguration<RoleV6> rolesV6 = (SecurityDynamicConfiguration<RoleV6>) load(
                CType.ROLES,
                true,
                acceptInvalid
            );
            final SecurityDynamicConfiguration<RoleMappingsV6> rolesmappingV6 = (SecurityDynamicConfiguration<RoleMappingsV6>) load(
                CType.ROLESMAPPING,
                true,
                acceptInvalid
            );
            final SecurityDynamicConfiguration<AuditConfig> auditConfigV6 = (SecurityDynamicConfiguration<AuditConfig>) load(
                CType.AUDIT,
                true
            );

            final SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsV7 = Migration.migrateActionGroups(actionGroupsV6);
            final SecurityDynamicConfiguration<ConfigV7> configV7 = Migration.migrateConfig(configV6);
            final SecurityDynamicConfiguration<InternalUserV7> internalUsersV7 = Migration.migrateInternalUsers(internalUsersV6);
            final Tuple<SecurityDynamicConfiguration<RoleV7>, SecurityDynamicConfiguration<TenantV7>> rolesTenantsV7 = Migration
                .migrateRoles(rolesV6, rolesmappingV6);
            final SecurityDynamicConfiguration<RoleMappingsV7> rolesmappingV7 = Migration.migrateRoleMappings(rolesmappingV6);
            final SecurityDynamicConfiguration<AuditConfig> auditConfigV7 = Migration.migrateAudit(auditConfigV6);

            ok(channel, "OK.");
        } catch (Exception e) {
            internalServerError(channel, "Configuration is not valid.");
        }
    }

    private SecurityDynamicConfiguration<?> load(final CType config, boolean logComplianceEvent, boolean acceptInvalid) {
        SecurityDynamicConfiguration<?> loaded = securityApiDependencies.configurationRepository()
            .getConfigurationsFromIndex(Collections.singleton(config), logComplianceEvent, acceptInvalid)
            .get(config)
            .deepClone();
        return DynamicConfigFactory.addStatics(loaded);
    }

}
