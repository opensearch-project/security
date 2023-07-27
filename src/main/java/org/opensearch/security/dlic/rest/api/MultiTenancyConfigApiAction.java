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
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.PUT;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class MultiTenancyConfigApiAction extends AbstractApiAction {

    private final static Logger LOGGER = LogManager.getLogger(MultiTenancyConfigApiAction.class);

    public static final String DEFAULT_TENANT_JSON_PROPERTY = "default_tenant";
    public static final String PRIVATE_TENANT_ENABLED_JSON_PROPERTY = "private_tenant_enabled";
    public static final String MULTITENANCY_ENABLED_JSON_PROPERTY = "multitenancy_enabled";

    private static final List<Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(new Route(GET, "/tenancy/config"), new Route(PUT, "/tenancy/config"))
    );

    private final static Set<String> ACCEPTABLE_DEFAULT_TENANTS = ImmutableSet.of(
        ConfigConstants.TENANCY_GLOBAL_TENANT_DEFAULT_NAME,
        ConfigConstants.TENANCY_GLOBAL_TENANT_NAME,
        ConfigConstants.TENANCY_PRIVATE_TENANT_NAME
    );

    @Override
    public String getName() {
        return "Multi Tenancy actions to Retrieve / Update configs.";
    }

    @Override
    public List<Route> routes() {
        return ROUTES;
    }

    public MultiTenancyConfigApiAction(
        final Settings settings,
        final Path configPath,
        final RestController controller,
        final Client client,
        final AdminDNs adminDNs,
        final ConfigurationRepository cl,
        final ClusterService cs,
        final PrincipalExtractor principalExtractor,
        final PrivilegesEvaluator evaluator,
        final ThreadPool threadPool,
        final AuditLog auditLog
    ) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
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
            public Map<String, DataType> allowedKeys() {
                return ImmutableMap.of(
                    DEFAULT_TENANT_JSON_PROPERTY,
                    DataType.STRING,
                    PRIVATE_TENANT_ENABLED_JSON_PROPERTY,
                    DataType.BOOLEAN,
                    MULTITENANCY_ENABLED_JSON_PROPERTY,
                    DataType.BOOLEAN
                );
            }
        });
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.TENANTS;
    }

    @Override
    protected String getResourceName() {
        return null;
    }

    @Override
    protected CType getConfigName() {
        return CType.CONFIG;
    }

    @Override
    protected void handleDelete(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content)
        throws IOException {
        notImplemented(channel, RestRequest.Method.DELETE);
    }

    private void multitenancyResponse(final ConfigV7 config, final RestChannel channel) {
        try (final XContentBuilder contentBuilder = channel.newBuilder()) {
            channel.sendResponse(
                new BytesRestResponse(
                    RestStatus.OK,
                    contentBuilder.startObject()
                        .field(DEFAULT_TENANT_JSON_PROPERTY, config.dynamic.kibana.default_tenant)
                        .field(PRIVATE_TENANT_ENABLED_JSON_PROPERTY, config.dynamic.kibana.private_tenant_enabled)
                        .field(MULTITENANCY_ENABLED_JSON_PROPERTY, config.dynamic.kibana.multitenancy_enabled)
                        .endObject()
                )
            );
        } catch (final Exception e) {
            internalErrorResponse(channel, e.getMessage());
            LOGGER.error("Error handle request ", e);
        }
    }

    @Override
    protected void handleGet(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content)
        throws IOException {
        final SecurityDynamicConfiguration<?> dynamicConfiguration = load(CType.CONFIG, false);
        final ConfigV7 config = (ConfigV7) dynamicConfiguration.getCEntry(CType.CONFIG.toLCString());
        multitenancyResponse(config, channel);
    }

    @Override
    protected void handlePut(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content)
        throws IOException {
        final SecurityDynamicConfiguration<ConfigV7> dynamicConfiguration = (SecurityDynamicConfiguration<ConfigV7>) load(
            CType.CONFIG,
            false
        );
        final ConfigV7 config = dynamicConfiguration.getCEntry(CType.CONFIG.toLCString());
        updateAndValidatesValues(config, content);
        dynamicConfiguration.putCEntry(CType.CONFIG.toLCString(), config);
        saveAndUpdateConfigs(this.securityIndexName, client, getConfigName(), dynamicConfiguration, new OnSucessActionListener<>(channel) {
            @Override
            public void onResponse(IndexResponse response) {
                multitenancyResponse(config, channel);
            }
        });
    }

    private void updateAndValidatesValues(final ConfigV7 config, final JsonNode jsonContent) {
        if (Objects.nonNull(jsonContent.findValue(DEFAULT_TENANT_JSON_PROPERTY))) {
            config.dynamic.kibana.default_tenant = jsonContent.findValue(DEFAULT_TENANT_JSON_PROPERTY).asText();
        }
        if (Objects.nonNull(jsonContent.findValue(PRIVATE_TENANT_ENABLED_JSON_PROPERTY))) {
            config.dynamic.kibana.private_tenant_enabled = jsonContent.findValue(PRIVATE_TENANT_ENABLED_JSON_PROPERTY).booleanValue();
        }
        if (Objects.nonNull(jsonContent.findValue(MULTITENANCY_ENABLED_JSON_PROPERTY))) {
            config.dynamic.kibana.multitenancy_enabled = jsonContent.findValue(MULTITENANCY_ENABLED_JSON_PROPERTY).asBoolean();
        }
        final String defaultTenant = Optional.ofNullable(config.dynamic.kibana.default_tenant).map(String::toLowerCase).orElse("");

        if (!config.dynamic.kibana.private_tenant_enabled && ConfigConstants.TENANCY_PRIVATE_TENANT_NAME.equals(defaultTenant)) {
            throw new IllegalArgumentException("Private tenant can not be disabled if it is the default tenant.");
        }

        if (ACCEPTABLE_DEFAULT_TENANTS.contains(defaultTenant)) {
            return;
        }

        final Set<String> availableTenants = cl.getConfiguration(CType.TENANTS)
            .getCEntries()
            .keySet()
            .stream()
            .map(String::toLowerCase)
            .collect(Collectors.toSet());
        if (!availableTenants.contains(defaultTenant)) {
            throw new IllegalArgumentException(
                config.dynamic.kibana.default_tenant
                    + " can not be set to default tenant. Default tenant should be selected from one of the available tenants."
            );
        }
    }

}
