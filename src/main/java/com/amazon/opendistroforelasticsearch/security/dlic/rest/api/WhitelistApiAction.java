/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.WhitelistValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;


/**
 * This class implements GET and PUT operations to manage dynamic WhitelistingSettings.
 * <p>
 * These APIs are only accessible to SuperAdmin since the configuration controls what APIs are accessible by normal users.
 * Eg: If whitelisting is enabled, and a specific API like "/_cat/nodes" is not whitelisted, then only the SuperAdmin can use "/_cat/nodes"
 * These APIs allow the SuperAdmin to enable/disable whitelisting, and also change the list of whitelisted APIs.
 * <p>
 * A SuperAdmin is identified by a certificate which represents a distinguished name(DN).
 * SuperAdmin DN's can be set in {@link ConfigConstants#OPENDISTRO_SECURITY_AUTHCZ_ADMIN_DN}
 * SuperAdmin certificate for the default superuser is stored as a kirk.pem file in config folder of OpenSearch
 * <p>
 * Example calling the PUT API as SuperAdmin using curl (if http basic auth is on):
 * curl -v --cacert path_to_config/root-ca.pem --cert path_to_config/kirk.pem --key path_to_config/kirk-key.pem -XPUT https://localhost:9200/_opendistro/_security/api/whitelist -H "Content-Type: application/json" -d’
 * {
 *      "enabled" : false,
 *      "requests" : {"/_cat/nodes": ["GET"], "/_opendistro/_security/api/whitelist": ["GET"]}
 * }
 *
 * Example using the PATCH API to change the requests as SuperAdmin:
 * curl -v --cacert path_to_config/root-ca.pem --cert path_to_config/kirk.pem --key path_to_config/kirk-key.pem -XPATCH https://localhost:9200/_opendistro/_security/api/whitelist -H "Content-Type: application/json" -d’
 * {
 *      "op":"replace",
 *      "path":"/config/requests",
 *      "value": {"/_cat/nodes": ["GET"], "/_opendistro/_security/api/whitelist": ["GET"]}
 * }
 *
 * To update enabled, use the "add" operation instead of the "replace" operation, since boolean variables are not recognized as valid paths when they are false.
 * eg:
 * curl -v --cacert path_to_config/root-ca.pem --cert path_to_config/kirk.pem --key path_to_config/kirk-key.pem -XPATCH https://localhost:9200/_opendistro/_security/api/whitelist -H "Content-Type: application/json" -d’
 * {
 *      "op":"add",
 *      "path":"/config/enabled",
 *      "value": true
 * }
 *
 * The backing data is stored in {@link ConfigConstants#OPENDISTRO_SECURITY_CONFIG_INDEX_NAME} which is populated during bootstrap.
 * For existing clusters, {@link com.amazon.opendistroforelasticsearch.security.tools.OpenDistroSecurityAdmin} tool can
 * be used to populate the index.
 * <p>
 */
public class WhitelistApiAction extends PatchableResourceApiAction {
    private static final List<Route> routes = ImmutableList.of(
            new Route(RestRequest.Method.GET, "/_opendistro/_security/api/whitelist"),
            new Route(RestRequest.Method.PUT, "/_opendistro/_security/api/whitelist"),
            new Route(RestRequest.Method.PATCH, "/_opendistro/_security/api/whitelist")
    );

    private static final String name = "config";

    @Inject
    public WhitelistApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                              final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
                              final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
    }

    @Override
    protected void handleApiRequest(final RestChannel channel, final RestRequest request, final Client client) throws IOException {
        if (!isSuperAdmin()) {
            forbidden(channel, "API allowed only for super admin.");
            return;
        }
        super.handleApiRequest(channel, request, client);
    }

    @Override
    protected void handleGet(final RestChannel channel, RestRequest request, Client client, final JsonNode content)
            throws IOException {


        final SecurityDynamicConfiguration<?> configuration = load(getConfigName(), true);
        filter(configuration);
        successResponse(channel, configuration);
    }

    @Override
    protected void handleDelete(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        notImplemented(channel, RestRequest.Method.DELETE);
    }

    @Override
    protected void handlePut(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        final SecurityDynamicConfiguration<?> existingConfiguration = load(getConfigName(), false);

        if (existingConfiguration.getSeqNo() < 0) {
            forbidden(channel, "Security index need to be updated to support '" + getConfigName().toLCString() + "'. Use OpenDistroSecurityAdmin to populate.");
            return;
        }

        boolean existed = existingConfiguration.exists(name);
        existingConfiguration.putCObject(name, DefaultObjectMapper.readTree(content, existingConfiguration.getImplementingClass()));

        saveAnUpdateConfigs(client, request, getConfigName(), existingConfiguration, new OnSucessActionListener<IndexResponse>(channel) {

            @Override
            public void onResponse(IndexResponse response) {
                if (existed) {
                    successResponse(channel, "'" + name + "' updated.");
                } else {
                    createdResponse(channel, "'" + name + "' created.");
                }
            }
        });
    }


    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.WHITELIST;
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
        return new WhitelistValidator(request, ref, this.settings, param);
    }

    @Override
    protected String getResourceName() {
        return name;
    }

    @Override
    protected CType getConfigName() {
        return CType.WHITELIST;
    }

}
