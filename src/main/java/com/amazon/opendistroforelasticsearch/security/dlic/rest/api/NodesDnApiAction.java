/*
 * Portions Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.NodesDnValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.NodesDn;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

/**
 * This class implements CRUD operations to manage dynamic NodesDn. The primary usecase is targeted at cross-cluster where
 * in node restart can be avoided by populating the coordinating cluster's nodes_dn values.
 *
 * The APIs are only accessible to SuperAdmin since the configuration controls the core application layer trust validation.
 * By default the APIs are disabled and can be enabled by a YML setting - {@link ConfigConstants#OPENDISTRO_SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED}
 *
 * The backing data is stored in {@link ConfigConstants#OPENDISTRO_SECURITY_CONFIG_INDEX_NAME} which is populated during bootstrap.
 * For existing clusters, {@link com.amazon.opendistroforelasticsearch.security.tools.OpenDistroSecurityAdmin} tool can
 * be used to populate the index.
 *
 * See {@link com.amazon.opendistroforelasticsearch.security.dlic.rest.api.NodesDnApiTest} for usage examples.
 */
public class NodesDnApiAction extends PatchableResourceApiAction {
    public static final String STATIC_ES_YML_NODES_DN = "STATIC_ES_YML_NODES_DN";
    private final List<String> staticNodesDnFromEsYml;

    private static final List<Route> routes = ImmutableList.of(
            new Route(Method.GET, "/_opendistro/_security/api/nodesdn/{name}"),
            new Route(Method.GET, "/_opendistro/_security/api/nodesdn/"),
            new Route(Method.DELETE, "/_opendistro/_security/api/nodesdn/{name}"),
            new Route(Method.PUT, "/_opendistro/_security/api/nodesdn/{name}"),
            new Route(Method.PATCH, "/_opendistro/_security/api/nodesdn/"),
            new Route(Method.PATCH, "/_opendistro/_security/api/nodesdn/{name}")
    );

    @Inject
    public NodesDnApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
        final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
        final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
        this.staticNodesDnFromEsYml = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_NODES_DN, Collections.emptyList());
    }

    @Override
    public List<Route> routes() {
        if (settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, false)) {
            return routes;
        }
        return Collections.emptyList();
    }

    @Override
    protected void handleApiRequest(RestChannel channel, RestRequest request, Client client) throws IOException {
        if (!isSuperAdmin()) {
            forbidden(channel, "API allowed only for admin.");
            return;
        }
        super.handleApiRequest(channel, request, client);
    }

    protected void consumeParameters(final RestRequest request) {
        request.param("name");
        request.param("show_all");
    }

    @Override
    protected boolean isReadOnly(SecurityDynamicConfiguration<?> existingConfiguration, String name) {
        if (STATIC_ES_YML_NODES_DN.equals(name)) {
            return true;
        }
        return super.isReadOnly(existingConfiguration, name);
    }

    @Override
    protected void handleGet(final RestChannel channel, RestRequest request, Client client, final JsonNode content) throws IOException {
        final String resourcename = request.param("name");

        final SecurityDynamicConfiguration<?> configuration = load(getConfigName(), true);
        filter(configuration);

        // no specific resource requested, return complete config
        if (resourcename == null || resourcename.length() == 0) {
            final Boolean showAll = request.paramAsBoolean("show_all", Boolean.FALSE);
            if (showAll) {
                putStaticEntry(configuration);
            }
            successResponse(channel, configuration);
            return;
        }

        if (!configuration.exists(resourcename)) {
            notFound(channel, "Resource '" + resourcename + "' not found.");
            return;
        }

        configuration.removeOthers(resourcename);
        successResponse(channel, configuration);
    }

    private void putStaticEntry(SecurityDynamicConfiguration<?> configuration) {
        if (NodesDn.class.equals(configuration.getImplementingClass())) {
            NodesDn nodesDn = new NodesDn();
            nodesDn.setNodesDn(staticNodesDnFromEsYml);
            ((SecurityDynamicConfiguration<NodesDn>)configuration).putCEntry(STATIC_ES_YML_NODES_DN, nodesDn);
        } else {
            throw new RuntimeException("Unknown class type - " + configuration.getImplementingClass());
        }
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.NODESDN;
    }

    @Override
    protected String getResourceName() {
        return "nodesdn";
    }

    @Override
    protected CType getConfigName() {
        return CType.NODESDN;
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params) {
        return new NodesDnValidator(request, ref, this.settings, params);
    }
}
