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

// CS-SUPPRESS-SINGLE: RegexpSingleline https://github.com/opensearch-project/OpenSearch/issues/3663

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.LegacyESVersion;
import org.opensearch.Version;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkRequestBuilder;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.Settings.Builder;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.securityconf.Migration;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.NodesDn;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.WhitelistingSettings;
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
// CS-ENFORCE-SINGLE

public class MigrateApiAction extends AbstractApiAction {
    private final static Logger LOGGER = LogManager.getLogger(MigrateApiAction.class);

    private static final List<Route> routes = addRoutesPrefix(Collections.singletonList(new Route(Method.POST, "/migrate")));

    @Inject
    public MigrateApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super(Endpoint.MIGRATE, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(this::migrateApiRequestHandlers);
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
        // not needed
    }

    private void migrateApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.allMethodsNotImplemented().override(Method.POST, (channel, request, client) -> migrate(channel, client));
    }

    @SuppressWarnings("unchecked")
    protected void migrate(final RestChannel channel, final Client client) throws IOException {

        final Version oldestNodeVersion = clusterService.state().getNodes().getMinNodeVersion();

        if (oldestNodeVersion.before(LegacyESVersion.V_7_0_0)) {
            badRequest(channel, "Can not migrate configuration because cluster is not fully migrated.");
            return;
        }

        final SecurityDynamicConfiguration<?> loadedConfig = load(CType.CONFIG, true);

        if (loadedConfig.getVersion() != 1) {
            badRequest(channel, "Can not migrate configuration because it was already migrated.");
            return;
        }

        final SecurityDynamicConfiguration<ConfigV6> configV6 = (SecurityDynamicConfiguration<ConfigV6>) loadedConfig;
        final SecurityDynamicConfiguration<ActionGroupsV6> actionGroupsV6 = (SecurityDynamicConfiguration<ActionGroupsV6>) load(
            CType.ACTIONGROUPS,
            true
        );
        final SecurityDynamicConfiguration<InternalUserV6> internalUsersV6 = (SecurityDynamicConfiguration<InternalUserV6>) load(
            CType.INTERNALUSERS,
            true
        );
        final SecurityDynamicConfiguration<RoleV6> rolesV6 = (SecurityDynamicConfiguration<RoleV6>) load(CType.ROLES, true);
        final SecurityDynamicConfiguration<RoleMappingsV6> rolesmappingV6 = (SecurityDynamicConfiguration<RoleMappingsV6>) load(
            CType.ROLESMAPPING,
            true
        );
        final SecurityDynamicConfiguration<NodesDn> nodesDnV6 = (SecurityDynamicConfiguration<NodesDn>) load(CType.NODESDN, true);
        final SecurityDynamicConfiguration<WhitelistingSettings> whitelistingSettingV6 = (SecurityDynamicConfiguration<
            WhitelistingSettings>) load(CType.WHITELIST, true);
        final SecurityDynamicConfiguration<AuditConfig> auditConfigV6 = (SecurityDynamicConfiguration<AuditConfig>) load(CType.AUDIT, true);

        final ImmutableList.Builder<SecurityDynamicConfiguration<?>> builder = ImmutableList.builder();

        final SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsV7 = Migration.migrateActionGroups(actionGroupsV6);
        builder.add(actionGroupsV7);
        final SecurityDynamicConfiguration<ConfigV7> configV7 = Migration.migrateConfig(configV6);
        builder.add(configV7);
        final SecurityDynamicConfiguration<InternalUserV7> internalUsersV7 = Migration.migrateInternalUsers(internalUsersV6);
        builder.add(internalUsersV7);
        final Tuple<SecurityDynamicConfiguration<RoleV7>, SecurityDynamicConfiguration<TenantV7>> rolesTenantsV7 = Migration.migrateRoles(
            rolesV6,
            rolesmappingV6
        );
        builder.add(rolesTenantsV7.v1());
        builder.add(rolesTenantsV7.v2());
        final SecurityDynamicConfiguration<RoleMappingsV7> rolesmappingV7 = Migration.migrateRoleMappings(rolesmappingV6);
        builder.add(rolesmappingV7);
        final SecurityDynamicConfiguration<NodesDn> nodesDnV7 = Migration.migrateNodesDn(nodesDnV6);
        builder.add(nodesDnV7);
        final SecurityDynamicConfiguration<WhitelistingSettings> whitelistingSettingV7 = Migration.migrateWhitelistingSetting(
            whitelistingSettingV6
        );
        builder.add(whitelistingSettingV7);
        final SecurityDynamicConfiguration<AuditConfig> auditConfigV7 = Migration.migrateAudit(auditConfigV6);
        builder.add(auditConfigV7);

        final int replicas = clusterService.state().metadata().index(securityApiDependencies.securityIndexName()).getNumberOfReplicas();
        final String autoExpandReplicas = clusterService.state()
            .metadata()
            .index(securityApiDependencies.securityIndexName())
            .getSettings()
            .get(IndexMetadata.SETTING_AUTO_EXPAND_REPLICAS);

        final Builder securityIndexSettings = Settings.builder();

        if (autoExpandReplicas == null) {
            securityIndexSettings.put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, replicas);
        } else {
            securityIndexSettings.put(IndexMetadata.SETTING_AUTO_EXPAND_REPLICAS, autoExpandReplicas);
        }

        securityIndexSettings.put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1);

        client.admin()
            .indices()
            .prepareDelete(securityApiDependencies.securityIndexName())
            .execute(new ActionListener<AcknowledgedResponse>() {

                @Override
                public void onResponse(AcknowledgedResponse response) {

                    if (response.isAcknowledged()) {
                        LOGGER.debug("opendistro_security index deleted successfully");

                        client.admin()
                            .indices()
                            .prepareCreate(securityApiDependencies.securityIndexName())
                            .setSettings(securityIndexSettings)
                            .execute(new ActionListener<CreateIndexResponse>() {

                                @Override
                                public void onResponse(CreateIndexResponse response) {
                                    final List<SecurityDynamicConfiguration<?>> dynamicConfigurations = builder.build();
                                    final ImmutableList.Builder<String> cTypes = ImmutableList.builderWithExpectedSize(
                                        dynamicConfigurations.size()
                                    );
                                    final BulkRequestBuilder br = client.prepareBulk(securityApiDependencies.securityIndexName());
                                    br.setRefreshPolicy(RefreshPolicy.IMMEDIATE);
                                    try {
                                        for (SecurityDynamicConfiguration<?> dynamicConfiguration : dynamicConfigurations) {
                                            final String id = dynamicConfiguration.getCType().toLCString();
                                            final BytesReference xContent = XContentHelper.toXContent(
                                                dynamicConfiguration,
                                                XContentType.JSON,
                                                false
                                            );
                                            br.add(new IndexRequest().id(id).source(id, xContent));
                                            cTypes.add(id);
                                        }
                                    } catch (final IOException e1) {
                                        LOGGER.error("Unable to create bulk request " + e1, e1);
                                        internalServerError(channel, "Unable to create bulk request.");
                                        return;
                                    }

                                    br.execute(
                                        new ConfigUpdatingActionListener<>(
                                            cTypes.build().toArray(new String[0]),
                                            client,
                                            new ActionListener<BulkResponse>() {

                                                @Override
                                                public void onResponse(BulkResponse response) {
                                                    if (response.hasFailures()) {
                                                        LOGGER.error(
                                                            "Unable to upload migrated configuration because of "
                                                                + response.buildFailureMessage()
                                                        );
                                                        internalServerError(
                                                            channel,
                                                            "Unable to upload migrated configuration (bulk index failed)."
                                                        );
                                                    } else {
                                                        LOGGER.debug("Migration completed");
                                                        ok(channel, "Migration completed.");
                                                    }

                                                }

                                                @Override
                                                public void onFailure(Exception e) {
                                                    LOGGER.error("Unable to upload migrated configuration because of " + e, e);
                                                    internalServerError(channel, "Unable to upload migrated configuration.");
                                                }
                                            }
                                        )
                                    );

                                }

                                @Override
                                public void onFailure(Exception e) {
                                    LOGGER.error("Unable to create opendistro_security index because of " + e, e);
                                    internalServerError(channel, "Unable to create opendistro_security index.");
                                }
                            });

                    } else {
                        LOGGER.error("Unable to create opendistro_security index.");
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    LOGGER.error("Unable to delete opendistro_security index because of " + e, e);
                    internalServerError(channel, "Unable to delete opendistro_security index.");
                }
            });

    }

}
