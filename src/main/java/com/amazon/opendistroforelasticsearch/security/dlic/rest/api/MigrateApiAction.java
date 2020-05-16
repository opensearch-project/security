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

import org.elasticsearch.Version;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.bulk.BulkRequestBuilder;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.Settings.Builder;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
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

        final SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsV7 = Migration.migrateActionGroups(actionGroupsV6);
        final SecurityDynamicConfiguration<ConfigV7> configV7 = Migration.migrateConfig(configV6);
        final SecurityDynamicConfiguration<InternalUserV7> internalUsersV7 = Migration.migrateInternalUsers(internalUsersV6);
        final Tuple<SecurityDynamicConfiguration<RoleV7>, SecurityDynamicConfiguration<TenantV7>> rolesTenantsV7 = Migration.migrateRoles(rolesV6,
                rolesmappingV6);
        final SecurityDynamicConfiguration<RoleMappingsV7> rolesmappingV7 = Migration.migrateRoleMappings(rolesmappingV6);
        final SecurityDynamicConfiguration<NodesDn> nodesDnV7 = Migration.migrateNodesDn(nodesDnV6);

        final int replicas = cs.state().metaData().index(opendistroIndex).getNumberOfReplicas();
        final String autoExpandReplicas = cs.state().metaData().index(opendistroIndex).getSettings().get(IndexMetaData.SETTING_AUTO_EXPAND_REPLICAS);

        final Builder securityIndexSettings = Settings.builder();

        if (autoExpandReplicas == null) {
            securityIndexSettings.put(IndexMetaData.SETTING_NUMBER_OF_REPLICAS, replicas);
        } else {
            securityIndexSettings.put(IndexMetaData.SETTING_AUTO_EXPAND_REPLICAS, autoExpandReplicas);
        }

        securityIndexSettings.put(IndexMetaData.SETTING_NUMBER_OF_SHARDS, 1);

        client.admin().indices().prepareDelete(this.opendistroIndex).execute(new ActionListener<AcknowledgedResponse>() {

            @Override
            public void onResponse(AcknowledgedResponse response) {

                if (response.isAcknowledged()) {
                    log.debug("opendistro_security index deleted successfully");

                    client.admin().indices().prepareCreate(opendistroIndex).setSettings(securityIndexSettings)
                            .execute(new ActionListener<CreateIndexResponse>() {

                                @Override
                                public void onResponse(CreateIndexResponse response) {

                                    final BulkRequestBuilder br = client.prepareBulk(opendistroIndex, "_doc");
                                    br.setRefreshPolicy(RefreshPolicy.IMMEDIATE);
                                    try {
                                        br.add(new IndexRequest().id(CType.CONFIG.toLCString()).source(CType.CONFIG.toLCString(),
                                                XContentHelper.toXContent(configV7, XContentType.JSON, false)));
                                        br.add(new IndexRequest().id(CType.ACTIONGROUPS.toLCString()).source(CType.ACTIONGROUPS.toLCString(),
                                                XContentHelper.toXContent(actionGroupsV7, XContentType.JSON, false)));
                                        br.add(new IndexRequest().id(CType.INTERNALUSERS.toLCString()).source(CType.INTERNALUSERS.toLCString(),
                                                XContentHelper.toXContent(internalUsersV7, XContentType.JSON, false)));
                                        br.add(new IndexRequest().id(CType.ROLES.toLCString()).source(CType.ROLES.toLCString(),
                                                XContentHelper.toXContent(rolesTenantsV7.v1(), XContentType.JSON, false)));
                                        br.add(new IndexRequest().id(CType.TENANTS.toLCString()).source(CType.TENANTS.toLCString(),
                                                XContentHelper.toXContent(rolesTenantsV7.v2(), XContentType.JSON, false)));
                                        br.add(new IndexRequest().id(CType.ROLESMAPPING.toLCString()).source(CType.ROLESMAPPING.toLCString(),
                                                XContentHelper.toXContent(rolesmappingV7, XContentType.JSON, false)));
                                        br.add(new IndexRequest().id(CType.NODESDN.toLCString()).source(CType.NODESDN.toLCString(),
                                                XContentHelper.toXContent(nodesDnV7, XContentType.JSON, false)));
                                    } catch (final IOException e1) {
                                        log.error("Unable to create bulk request " + e1, e1);
                                        internalErrorResponse(channel, "Unable to create bulk request.");
                                        return;
                                    }

                                    br.execute(new ConfigUpdatingActionListener(client, new ActionListener<BulkResponse>() {

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
