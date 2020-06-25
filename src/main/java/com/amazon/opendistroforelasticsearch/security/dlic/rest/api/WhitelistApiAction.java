package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.RolesMappingValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.WhitelistValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;


/**
 * This class implements GET and PUT operations to manage dynamic WhitelistingSettings.
 * <p>
 * These APIs are only accessible to SuperAdmin since the configuration controls what APIs are accessible by normal users.
 * Eg: If whitelisting is enabled, and a specific API like "/_cat/nodes" is not whitelisted, then only the SuperAdmin can use "/_cat/nodes"st
 * These APIs allow the SuperAdmin to enable/disable whitelisting, and also change the list of whitelisted APIs.
 * <p>
 * A SuperAdmin is identified by a certificate which represents a distinguished name(DN).
 * SuperAdmin DN's can be set in {@link ConfigConstants#OPENDISTRO_SECURITY_AUTHCZ_ADMIN_DN}
 * SuperAdmin certificate for the default superuser is stored as a kirk.pem file in config folder of elasticsearch
 * <p>
 * Example calling the PUT API as SuperAdmin using curl (if http basic auth is on):
 * curl -v --cacert path_to_config/root-ca.pem --cert path_to_config/kirk.pem --key path_to_config/kirk-key.pem -XPUT https://localhost:9200/_opendistro/_security/api/whitelist -H "Content-Type: application/json" -d’
 * {
 * "whitelistingEnabled" : false,
 * "whitelistedAPIs" : ["/_cat/nodes","/_opendistro/_security/api/whitelist","/_opendistro/_security/api/securityconfig"]
 * }
 * ‘
 * <p>
 * Currently, whitelisting checks the path for equality, so make sure you don't have errors in the whitelisted APIs.
 * eg: whitelisting "/_cat/nodes/" is different from whitelisting /_cat/nodes" (extra '/' results in a different path
 * <p>
 * The backing data is stored in {@link ConfigConstants#OPENDISTRO_SECURITY_CONFIG_INDEX_NAME} which is populated during bootstrap.
 * For existing clusters, {@link com.amazon.opendistroforelasticsearch.security.tools.OpenDistroSecurityAdmin} tool can
 * be used to populate the index.
 * <p>
 */
public class WhitelistApiAction extends AbstractApiAction {
    private static final List<Route> routes = ImmutableList.of(
            new Route(RestRequest.Method.GET, "/_opendistro/_security/api/whitelist"),
            new Route(RestRequest.Method.PUT, "/_opendistro/_security/api/whitelist")
    );

    private static final String name = "whitelisting_settings";

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
        return;
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
        return Endpoint.WHITELISTING_SETTINGS;
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
        return CType.WHITELISTING_SETTINGS;
    }

}
