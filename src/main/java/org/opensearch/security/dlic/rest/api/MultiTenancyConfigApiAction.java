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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.RestChannel;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.DashboardSignInOption;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.securityconf.impl.v7.ConfigV7.Authc;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.PUT;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class MultiTenancyConfigApiAction extends AbstractApiAction {

    public static final String DEFAULT_TENANT_JSON_PROPERTY = "default_tenant";
    public static final String PRIVATE_TENANT_ENABLED_JSON_PROPERTY = "private_tenant_enabled";
    public static final String MULTITENANCY_ENABLED_JSON_PROPERTY = "multitenancy_enabled";
    public static final String SIGN_IN_OPTIONS = "sign_in_options";

    private static final List<Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(new Route(GET, "/tenancy/config"), new Route(PUT, "/tenancy/config"))
    );

    private final static Set<String> ACCEPTABLE_DEFAULT_TENANTS = Set.of(
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
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super(Endpoint.TENANTS, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(this::multiTenancyConfigApiRequestHandlers);
    }

    @Override
    protected CType getConfigType() {
        return CType.CONFIG;
    }

    @Override
    protected EndpointValidator createEndpointValidator() {
        return new EndpointValidator() {

            @Override
            public Endpoint endpoint() {
                return endpoint;
            }

            @Override
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return securityApiDependencies.restApiAdminPrivilegesEvaluator();
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
                    @Override
                    public Object[] params() {
                        return params;
                    }

                    @Override
                    public Settings settings() {
                        return securityApiDependencies.settings();
                    }

                    @Override
                    public Map<String, DataType> allowedKeys() {
                        return ImmutableMap.of(
                            DEFAULT_TENANT_JSON_PROPERTY,
                            DataType.STRING,
                            PRIVATE_TENANT_ENABLED_JSON_PROPERTY,
                            DataType.BOOLEAN,
                            MULTITENANCY_ENABLED_JSON_PROPERTY,
                            DataType.BOOLEAN,
                            SIGN_IN_OPTIONS,
                            DataType.ARRAY
                        );
                    }
                });
            }
        };
    }

    private ToXContent multitenancyContent(final ConfigV7 config) {
        return (builder, params) -> builder.startObject()
            .field(DEFAULT_TENANT_JSON_PROPERTY, config.dynamic.kibana.default_tenant)
            .field(PRIVATE_TENANT_ENABLED_JSON_PROPERTY, config.dynamic.kibana.private_tenant_enabled)
            .field(MULTITENANCY_ENABLED_JSON_PROPERTY, config.dynamic.kibana.multitenancy_enabled)
            .field(SIGN_IN_OPTIONS, config.dynamic.kibana.sign_in_options)
            .endObject();
    }

    private void multiTenancyConfigApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.allMethodsNotImplemented()
            .override(GET, (channel, request, client) -> loadConfiguration(getConfigType(), false, false).valid(configuration -> {
                final var config = (ConfigV7) configuration.getCEntry(CType.CONFIG.toLCString());
                ok(channel, multitenancyContent(config));
            }).error((status, toXContent) -> response(channel, status, toXContent)))
            .override(PUT, (channel, request, client) -> {
                loadConfigurationWithRequestContent("config", request).valid(
                    securityConfiguration -> updateMultitenancy(channel, client, securityConfiguration)
                ).error((status, toXContent) -> response(channel, status, toXContent));
            });
    }

    protected void updateMultitenancy(
        final RestChannel channel,
        final Client client,
        final SecurityConfiguration securityConfiguration

    ) throws IOException {
        @SuppressWarnings("unchecked")
        final var dynamicConfiguration = (SecurityDynamicConfiguration<ConfigV7>) securityConfiguration.configuration();
        final var config = dynamicConfiguration.getCEntry(CType.CONFIG.toLCString());
        updateAndValidatesValues(config, securityConfiguration.requestContent());
        dynamicConfiguration.putCEntry(CType.CONFIG.toLCString(), config);
        saveOrUpdateConfiguration(client, dynamicConfiguration, new OnSucessActionListener<>(channel) {
            @Override
            public void onResponse(IndexResponse indexResponse) {
                ok(channel, multitenancyContent(config));
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
        if (jsonContent.hasNonNull(SIGN_IN_OPTIONS) && jsonContent.findValue(SIGN_IN_OPTIONS).isEmpty() == false) {
            JsonNode newOptions = jsonContent.findValue(SIGN_IN_OPTIONS);
            List<DashboardSignInOption> options = getNewSignInOptions(newOptions, config.dynamic.authc);
            config.dynamic.kibana.sign_in_options = options;
        }

        final String defaultTenant = Optional.ofNullable(config.dynamic.kibana.default_tenant).map(String::toLowerCase).orElse("");

        if (!config.dynamic.kibana.private_tenant_enabled && ConfigConstants.TENANCY_PRIVATE_TENANT_NAME.equals(defaultTenant)) {
            throw new IllegalArgumentException("Private tenant can not be disabled if it is the default tenant.");
        }

        if (ACCEPTABLE_DEFAULT_TENANTS.contains(defaultTenant)) {
            return;
        }

        final Set<String> availableTenants = securityApiDependencies.configurationRepository()
            .getConfiguration(CType.TENANTS)
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

    private List<DashboardSignInOption> getNewSignInOptions(JsonNode newOptions, Authc authc) {

        Set<String> domains = authc.getDomains().keySet();

        return IntStream.range(0, newOptions.size()).mapToObj(newOptions::get).map(JsonNode::asText).filter(option -> {
            // Checking if the new sign-in options are set in backend.
            if (option.equals(DashboardSignInOption.ANONYMOUS.toString())
                || domains.stream().anyMatch(domain -> domain.contains(option.toLowerCase()))) {
                return true;
            } else {
                throw new IllegalArgumentException(
                    "Validation failure: " + option.toUpperCase() + " authentication provider is not available for this cluster."
                );
            }
        }).map(DashboardSignInOption::valueOf).collect(Collectors.toList());
    }
}
