/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.file.Path;

import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.threadpool.ThreadPool;

import com.fasterxml.jackson.databind.JsonNode;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.NoOpValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.Migration;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.ActionGroupsV6;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.ConfigV6;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.InternalUserV6;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.RoleMappingsV6;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.RoleV6;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ActionGroupsV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ConfigV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.InternalUserV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.RoleMappingsV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.RoleV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.TenantV7;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;

public class ValidateApiAction extends AbstractApiAction {

    @Inject
    public ValidateApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                             final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs, final PrincipalExtractor principalExtractor,
                             final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
    }

    @Override
    protected void registerHandlers(RestController controller, Settings settings) {
        controller.registerHandler(Method.GET, "/_opendistro/_security/api/validate", this);
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.VALIDATE;
    }

    @SuppressWarnings("unchecked")
    @Override
    protected void handleGet(RestChannel channel, RestRequest request, Client client, final JsonNode content) throws IOException {

        final boolean acceptInvalid = request.paramAsBoolean("accept_invalid", false);

        final SecurityDynamicConfiguration<?> loadedConfig = load(CType.CONFIG, true, acceptInvalid);

        if (loadedConfig.getVersion() != 1) {
            badRequestResponse(channel, "Can not migrate configuration because it was already migrated.");
            return;
        }

        try {
            final SecurityDynamicConfiguration<ConfigV6> configV6 = (SecurityDynamicConfiguration<ConfigV6>) loadedConfig;
            final SecurityDynamicConfiguration<ActionGroupsV6> actionGroupsV6 = (SecurityDynamicConfiguration<ActionGroupsV6>) load(CType.ACTIONGROUPS, true, acceptInvalid);
            final SecurityDynamicConfiguration<InternalUserV6> internalUsersV6 = (SecurityDynamicConfiguration<InternalUserV6>) load(CType.INTERNALUSERS, true, acceptInvalid);
            final SecurityDynamicConfiguration<RoleV6> rolesV6 = (SecurityDynamicConfiguration<RoleV6>) load(CType.ROLES, true, acceptInvalid);
            final SecurityDynamicConfiguration<RoleMappingsV6> rolesmappingV6 = (SecurityDynamicConfiguration<RoleMappingsV6>) load(CType.ROLESMAPPING, true, acceptInvalid);

            final SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsV7 = Migration.migrateActionGroups(actionGroupsV6);
            final SecurityDynamicConfiguration<ConfigV7> configV7 = Migration.migrateConfig(configV6);
            final SecurityDynamicConfiguration<InternalUserV7> internalUsersV7 = Migration.migrateInternalUsers(internalUsersV6);
            final Tuple<SecurityDynamicConfiguration<RoleV7>, SecurityDynamicConfiguration<TenantV7>> rolesTenantsV7 = Migration.migrateRoles(rolesV6,
                rolesmappingV6);
            final SecurityDynamicConfiguration<RoleMappingsV7> rolesmappingV7 = Migration.migrateRoleMappings(rolesmappingV6);

            successResponse(channel, "OK.");
        } catch (Exception e) {
            internalErrorResponse(channel, "Configuration is not valid.");
        }
    }

    @Override
    protected void handleDelete(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        notImplemented(channel, Method.POST);
    }

    @Override
    protected void handlePost(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        notImplemented(channel, Method.GET);
    }

    @Override
    protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        notImplemented(channel, Method.PUT);
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
        return new NoOpValidator(request, ref, this.settings, param);
    }

    @Override
    protected String getResourceName() {
        // not needed
        return null;
    }

    @Override
    protected CType getConfigName() {
        return null;
    }

    @Override
    protected void consumeParameters(final RestRequest request) {
        request.paramAsBoolean("accept_invalid", false);
    }

}