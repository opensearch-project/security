package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.configuration.StaticResourceException;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AuditValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Rest handler for fetching and updating audit configuration.
 * Supported REST endpoints
 * GET _opendistro/_security/api/audit/
 * {
 *   "config" : {
 *     "audit" : {
 *       "enable_rest" : true,
 *       "disabled_rest_categories" : [
 *         "GRANTED_PRIVILEGES",
 *         "SSL_EXCEPTION"
 *       ],
 *       "enable_transport" : true,
 *       "disabled_transport_categories" : [
 *         "GRANTED_PRIVILEGES",
 *         "AUTHENTICATED"
 *       ],
 *       "resolve_bulk_requests" : false,
 *       "log_request_body" : true,
 *       "resolve_indices" : true,
 *       "exclude_sensitive_headers" : true,
 *       "ignore_users" : [
 *         "kibanaserver"
 *       ],
 *       "ignore_requests" : [ ]
 *     },
 *     "compliance" : {
 *       "internal_config" : true,
 *       "external_config" : true,
 *       "read_metadata_only" : true,
 *       "read_watched_fields" : { },
 *       "read_ignore_users" : [ ],
 *       "write_metadata_only" : true,
 *       "write_log_diffs" : false,
 *       "write_watched_indices" : [ ],
 *       "write_ignore_users" : [ ]
 *     }
 *   }
 * }
 *
 * PUT _opendistro/_security/api/audit/config
 * {
 *   "audit":{
 *     "enable_rest":true,
 *     "disabled_rest_categories":[
 *       "GRANTED_PRIVILEGES",
 *       "SSL_EXCEPTION"
 *     ],
 *     "enable_transport":true,
 *     "disabled_transport_categories":[
 *       "GRANTED_PRIVILEGES",
 *       "AUTHENTICATED"
 *     ],
 *     "resolve_bulk_requests":false,
 *     "log_request_body":true,
 *     "resolve_indices":true,
 *     "exclude_sensitive_headers":true,
 *     "ignore_users":[ ],
 *     "ignore_requests":[ ]
 *   },
 *   "compliance":{
 *     "internal_config":true,
 *     "external_config":true,
 *     "read_metadata_only":true,
 *     "read_watched_fields":{ },
 *     "read_ignore_users":[ ],
 *     "write_metadata_only":true,
 *     "write_log_diffs":false,
 *     "write_watched_indices":[ ],
 *     "write_ignore_users":[ ]
 *   }
 * }
 *
 * PATCH _opendistro/_security/api/audit
 * [{"op": "replace", "path": "/config/audit/enable_rest", "value": "true"}]
 * [{"op": "replace", "path": "/config/compliance/internal_config", "value": "true"}]
 */
public class AuditApiAction extends PatchableResourceApiAction {
    private static final List<Route> routes = ImmutableList.of(
            new Route(RestRequest.Method.GET, "/_opendistro/_security/api/audit/"),
            new Route(RestRequest.Method.PUT, "/_opendistro/_security/api/audit/{name}"),
            new Route(RestRequest.Method.PATCH, "/_opendistro/_security/api/audit/")
    );

    private static final String RESOURCE_NAME = "config";
    @VisibleForTesting
    public static final String READONLY_FIELD = "_readonly";
    @VisibleForTesting
    public static final String STATIC_RESOURCE = "/static_config/static_audit.yml";
    private final List<String> readonlyFields;
    private final PrivilegesEvaluator privilegesEvaluator;
    private final ThreadContext threadContext;

    public AuditApiAction(final Settings settings,
                          final Path configPath,
                          final RestController controller,
                          final Client client,
                          final AdminDNs adminDNs,
                          final ConfigurationRepository cl,
                          final ClusterService cs,
                          final PrincipalExtractor principalExtractor,
                          final PrivilegesEvaluator privilegesEvaluator,
                          final ThreadPool threadPool,
                          final AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, privilegesEvaluator, threadPool, auditLog);
        this.privilegesEvaluator = privilegesEvaluator;
        this.threadContext = threadPool.getThreadContext();
        try {
            this.readonlyFields = DefaultObjectMapper.YAML_MAPPER
                    .readValue(this.getClass().getResourceAsStream(STATIC_RESOURCE), new TypeReference<Map<String, List<String>>>() {})
                    .get(READONLY_FIELD);
            if (!AuditConfig.FIELD_PATHS.containsAll(this.readonlyFields)) {
                throw new StaticResourceException("Invalid read-only field paths provided in static resource file " + STATIC_RESOURCE);
            }
        } catch (IOException e) {
            throw new StaticResourceException("Unable to load audit static resource file", e);
        }
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected void handleApiRequest(final RestChannel channel, final RestRequest request, final Client client) throws IOException {
        // if audit config doc is not available in security index,
        // disable audit APIs
        if (!cl.isAuditHotReloadingEnabled()) {
            notImplemented(channel, request.method());
            return;
        }
        super.handleApiRequest(channel, request, client);
    }

    @Override
    protected void handlePut(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        if (!RESOURCE_NAME.equals(request.param("name"))) {
            badRequestResponse(channel, "name must be config");
            return;
        }
        super.handlePut(channel, request, client, content);
    }

    @Override
    protected void handleGet(final RestChannel channel, RestRequest request, Client client, final JsonNode content) {
        final SecurityDynamicConfiguration<?> configuration = load(getConfigName(), true);
        filter(configuration);

        final String resourcename = getResourceName();
        if (!configuration.exists(resourcename)) {
            notFound(channel, "Resource '" + resourcename + "' not found.");
            return;
        }

        configuration.putCObject(READONLY_FIELD, readonlyFields);
        successResponse(channel, configuration);
    }

    @Override
    protected void handlePost(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) {
        notImplemented(channel, RestRequest.Method.POST);
    }

    @Override
    protected void handleDelete(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) {
        notImplemented(channel, RestRequest.Method.DELETE);
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params) {
        return new AuditValidator(request, ref, this.settings, params);
    }

    @Override
    protected String getResourceName() {
        return RESOURCE_NAME;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.AUDIT;
    }

    @Override
    protected CType getConfigName() {
        return CType.AUDIT;
    }

    @Override
    protected boolean isReadonlyFieldUpdated(final JsonNode existingResource, final JsonNode targetResource) {
        if (!isSuperAdmin()) {
            return readonlyFields
                    .stream()
                    .anyMatch(path -> !existingResource.at(path).equals(targetResource.at(path)));
        }
        return false;
    }

    @Override
    protected boolean isReadonlyFieldUpdated(final SecurityDynamicConfiguration<?> configuration, final JsonNode targetResource) {
        return isReadonlyFieldUpdated(Utils.convertJsonToJackson(configuration, false).get(getResourceName()), targetResource);
    }
}
