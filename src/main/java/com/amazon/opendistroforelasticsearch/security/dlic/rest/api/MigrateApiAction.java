/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import com.amazon.opendistroforelasticsearch.security.securityconf.impl.WhitelistingSettings;
import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import org.opensearch.Version;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkRequestBuilder;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.Settings.Builder;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.threadpool.ThreadPool;

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
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.NodesDn;
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

import com.google.common.collect.ImmutableList;

public class MigrateApiAction extends AbstractApiAction {
    private static final List<Route> routes = Collections.singletonList(
            new Route(Method.POST, "/_opendistro/_security/api/migrate")
    );

    @Inject
    public MigrateApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                            final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs, final PrincipalExtractor principalExtractor,
                            final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.MIGRATE;
    }

    @SuppressWarnings("unchecked")
    @Override
    protected void handlePost(RestChannel channel, RestRequest request, Client client, final JsonNode content) throws IOException {

        final Version oldestNodeVersion = cs.state().getNodes().getMinNodeVersion();

        if(oldestNodeVersion.before(Version.V_7_0_0)) {
            badRequestResponse(channel, "Can not migrate configuration because cluster is not fully migrated.");
            return;
        }

        final SecurityDynamicConfiguration<?> loadedConfig = load(CType.CONFIG, true);

        if (loadedConfig.getVersion() != 1) {
            badRequestResponse(channel, "Can not migrate configuration because it was already migrated.");
            return;
        }

        final SecurityDynamicConfiguration<ConfigV6> configV6 = (SecurityDynamicConfiguration<ConfigV6>) loadedConfig;
        final SecurityDynamicConfiguration<ActionGroupsV6> actionGroupsV6 = (SecurityDynamicConfiguration<ActionGroupsV6>) load(CType.ACTIONGROUPS, true);
        final SecurityDynamicConfiguration<InternalUserV6> internalUsersV6 = (SecurityDynamicConfiguration<InternalUserV6>) load(CType.INTERNALUSERS, true);
        final SecurityDynamicConfiguration<RoleV6> rolesV6 = (SecurityDynamicConfiguration<RoleV6>) load(CType.ROLES, true);
        final SecurityDynamicConfiguration<RoleMappingsV6> rolesmappingV6 = (SecurityDynamicConfiguration<RoleMappingsV6>) load(CType.ROLESMAPPING, true);
        final SecurityDynamicConfiguration<NodesDn> nodesDnV6 = (SecurityDynamicConfiguration<NodesDn>) load(CType.NODESDN, true);
        final SecurityDynamicConfiguration<WhitelistingSettings> whitelistingSettingV6 = (SecurityDynamicConfiguration<WhitelistingSettings>) load(CType.WHITELIST, true);
        final SecurityDynamicConfiguration<AuditConfig> auditConfigV6 = (SecurityDynamicConfiguration<AuditConfig>) load(CType.AUDIT, true);

        final ImmutableList.Builder<SecurityDynamicConfiguration<?>> builder = ImmutableList.builder();

        final SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsV7 = Migration.migrateActionGroups(actionGroupsV6);
        builder.add(actionGroupsV7);
        final SecurityDynamicConfiguration<ConfigV7> configV7 = Migration.migrateConfig(configV6);
        builder.add(configV7);
        final SecurityDynamicConfiguration<InternalUserV7> internalUsersV7 = Migration.migrateInternalUsers(internalUsersV6);
        builder.add(internalUsersV7);
        final Tuple<SecurityDynamicConfiguration<RoleV7>, SecurityDynamicConfiguration<TenantV7>> rolesTenantsV7 = Migration.migrateRoles(rolesV6,
                rolesmappingV6);
        builder.add(rolesTenantsV7.v1());
        builder.add(rolesTenantsV7.v2());
        final SecurityDynamicConfiguration<RoleMappingsV7> rolesmappingV7 = Migration.migrateRoleMappings(rolesmappingV6);
        builder.add(rolesmappingV7);
        final SecurityDynamicConfiguration<NodesDn> nodesDnV7 = Migration.migrateNodesDn(nodesDnV6);
        builder.add(nodesDnV7);
        final SecurityDynamicConfiguration<WhitelistingSettings> whitelistingSettingV7 = Migration.migrateWhitelistingSetting(whitelistingSettingV6);
        builder.add(whitelistingSettingV7);
        final SecurityDynamicConfiguration<AuditConfig> auditConfigV7 = Migration.migrateAudit(auditConfigV6);
        builder.add(auditConfigV7);

        final int replicas = cs.state().metadata().index(opendistroIndex).getNumberOfReplicas();
        final String autoExpandReplicas = cs.state().metadata().index(opendistroIndex).getSettings().get(IndexMetadata.SETTING_AUTO_EXPAND_REPLICAS);

        final Builder securityIndexSettings = Settings.builder();

        if (autoExpandReplicas == null) {
            securityIndexSettings.put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, replicas);
        } else {
            securityIndexSettings.put(IndexMetadata.SETTING_AUTO_EXPAND_REPLICAS, autoExpandReplicas);
        }

        securityIndexSettings.put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1);

        client.admin().indices().prepareDelete(this.opendistroIndex).execute(new ActionListener<AcknowledgedResponse>() {

            @Override
            public void onResponse(AcknowledgedResponse response) {

                if (response.isAcknowledged()) {
                    log.debug("opendistro_security index deleted successfully");

                    client.admin().indices().prepareCreate(opendistroIndex).setSettings(securityIndexSettings)
                            .execute(new ActionListener<CreateIndexResponse>() {

                                @Override
                                public void onResponse(CreateIndexResponse response) {
                                    final List<SecurityDynamicConfiguration<?>> dynamicConfigurations = builder.build();
                                    final ImmutableList.Builder<String> cTypes = ImmutableList.builderWithExpectedSize(dynamicConfigurations.size());
                                    final BulkRequestBuilder br = client.prepareBulk(opendistroIndex, "_doc");
                                    br.setRefreshPolicy(RefreshPolicy.IMMEDIATE);
                                    try {
                                        for (SecurityDynamicConfiguration dynamicConfiguration : dynamicConfigurations) {
                                            final String id = dynamicConfiguration.getCType().toLCString();
                                            final BytesReference xContent = XContentHelper.toXContent(dynamicConfiguration, XContentType.JSON, false);
                                            br.add(new IndexRequest().id(id).source(id, xContent));
                                            cTypes.add(id);
                                        }
                                    } catch (final IOException e1) {
                                        log.error("Unable to create bulk request " + e1, e1);
                                        internalErrorResponse(channel, "Unable to create bulk request.");
                                        return;
                                    }

                                    br.execute(new ConfigUpdatingActionListener(cTypes.build().toArray(new String[0]), client, new ActionListener<BulkResponse>() {

                                        @Override
                                        public void onResponse(BulkResponse response) {
                                            if (response.hasFailures()) {
                                                log.error("Unable to upload migrated configuration because of " + response.buildFailureMessage());
                                                internalErrorResponse(channel, "Unable to upload migrated configuration (bulk index failed).");
                                            } else {
                                                log.debug("Migration completed");
                                                successResponse(channel, "Migration completed.");
                                            }

                                        }

                                        @Override
                                        public void onFailure(Exception e) {
                                            log.error("Unable to upload migrated configuration because of " + e, e);
                                            internalErrorResponse(channel, "Unable to upload migrated configuration.");
                                        }
                                    }));

                                }

                                @Override
                                public void onFailure(Exception e) {
                                    log.error("Unable to create opendistro_security index because of " + e, e);
                                    internalErrorResponse(channel, "Unable to create opendistro_security index.");
                                }
                            });

                } else {
                    log.error("Unable to create opendistro_security index.");
                }
            }

            @Override
            public void onFailure(Exception e) {
                log.error("Unable to delete opendistro_security index because of " + e, e);
                internalErrorResponse(channel, "Unable to delete opendistro_security index.");
            }
        });

    }

    @Override
    protected void handleDelete(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        notImplemented(channel, Method.POST);
    }

    @Override
    protected void handleGet(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
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
        // not needed
    }

}
