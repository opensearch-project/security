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

import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static org.opensearch.security.dlic.rest.support.Utils.withIOException;

import java.io.IOException;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigHelper;
import org.opensearch.threadpool.ThreadPool;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.flipkart.zjsonpatch.DiffFlags;
import com.flipkart.zjsonpatch.JsonDiff;
import com.google.common.collect.ImmutableList;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigHelper;
import org.opensearch.threadpool.ThreadPool;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flipkart.zjsonpatch.DiffFlags;
import com.flipkart.zjsonpatch.JsonDiff;
import com.google.common.collect.ImmutableList;


public class ConfigUpgradeApiAction extends AbstractApiAction {

    private final static Logger LOGGER = LogManager.getLogger(ConfigUpgradeApiAction.class);

    private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
        new Route(Method.GET, "/_upgrade_check"),
        new Route(Method.POST, "/_upgrade_perform")));

    @Inject
    public ConfigUpgradeApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super(Endpoint.CONFIG, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(rhb -> {
            rhb.allMethodsNotImplemented().add(Method.GET, this::handleCanUpgrade).add(Method.POST, this::handleUpgrade);
        });
    }

    void handleCanUpgrade(final RestChannel channel, final RestRequest request, final Client client) throws IOException {
        withIOException(() -> getAndValidateConfigurationsToUpgrade(request)
            .map(configurations -> {
                final var differencesList = new ArrayList<ValidationResult<Tuple<CType, JsonNode>>>();
                for (final var configuration : configurations) {
                    differencesList.add(computeDifferenceToUpdate(configuration)
                        .map(differences -> ValidationResult.success(new Tuple<CType, JsonNode>(configuration, differences.deepCopy()))));
                }
                return ValidationResult.combine(differencesList);
            }))
            .valid(differencesList -> {
                final var canUpgrade = differencesList.stream().anyMatch(entry -> entry.v2().size() > 0);

                final ObjectNode response = JsonNodeFactory.instance.objectNode();
                response.put("can_upgrade", canUpgrade);
    
                if (canUpgrade) {
                    final ObjectNode differences = JsonNodeFactory.instance.objectNode();
                    differencesList.forEach(t -> {
                        differences.put(t.v1().toLCString(), t.v2());
                    });
                    response.put("differences", differences);
                }
                channel.sendResponse(new BytesRestResponse(RestStatus.OK, XContentType.JSON.mediaType(), response.toPrettyString()));
            })
            .error((status, toXContent) -> response(channel, status, toXContent));
    }

    private void handleUpgrade(final RestChannel channel, final RestRequest request, final Client client) throws IOException {
        throw new UnsupportedOperationException("Unimplemented method 'handleUpgrade'");
    }

    private ValidationResult<JsonNode> computeDifferenceToUpdate(final CType configType) throws IOException {
        return loadConfiguration(configType, false, false).map(activeRoles -> {
            final var activeRolesJson = Utils.convertJsonToJackson(activeRoles, false);
            final var defaultRolesJson = loadConfigFileAsJson(configType);
            final var rawDiff = JsonDiff.asJson(activeRolesJson, defaultRolesJson, EnumSet.of(DiffFlags.OMIT_VALUE_ON_REMOVE));
            return ValidationResult.success(filterRemoveOperations(rawDiff));
        });
    }

    private ValidationResult<Set<CType>> getAndValidateConfigurationsToUpgrade(final RestRequest request) {
        final String[] configs = request.paramAsStringArray("configs", null);
        
        final var configurations = Optional.ofNullable(configs)
            .map(CType::fromStringValues)
            .orElse(supportedConfigs());

        if (!configurations.stream().allMatch(supportedConfigs()::contains)) {
            // Remove all supported configurations
            configurations.removeAll(supportedConfigs());
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("Unsupported configurations for upgrade" + configurations)); 
        }

        return ValidationResult.success(configurations);
    }

    private Set<CType> supportedConfigs() {
        return Set.of(CType.ROLES);
    }

    private JsonNode filterRemoveOperations(final JsonNode diff) {
        final ArrayNode filteredDiff = JsonNodeFactory.instance.arrayNode();
        diff.forEach(node -> {
            if (!isRemoveOperation(node)) {
                filteredDiff.add(node.deepCopy());
                return;
            } else {
                if (!hasRootLevelPath(node)) {
                    filteredDiff.add(node.deepCopy());
                }
            }
        });
        return filteredDiff;
    }

    private boolean hasRootLevelPath(final JsonNode node) {
        final var jsonPath = node.get("path").asText();
        return jsonPath.charAt(0) == '/' && !jsonPath.substring(1).contains("/");
    }

    private boolean isRemoveOperation(final JsonNode node) {
        return node.get("op").asText().equals("remove");
    }

    public JsonNode loadConfigFileAsJson(final CType cType) throws IOException {
        final var cd = securityApiDependencies.configurationRepository().getConfigDirectory();
        final var filepath = cType.configFile(Path.of(cd)).toString();
        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<JsonNode>) () -> {
                var loadedConfiguration = ConfigHelper.fromYamlFile(filepath, cType, ConfigurationRepository.DEFAULT_CONFIG_VERSION, 0, 0);
                return Utils.convertJsonToJackson(loadedConfiguration, false);
            });
        } catch (final PrivilegedActionException e) {
            LOGGER.error("Error when loading configuration from file", e);
            throw (IOException) e.getCause();
        }
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType getConfigType() {
        return CType.ROLES;
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
            public RequestContentValidator createRequestContentValidator(final Object... params) {
                return RequestContentValidator.of(new RequestContentValidator.ValidationContext() {

                    @Override
                    public Set<String> mandatoryKeys() {
                        return Set.of("configs");
                    }

                    @Override
                    public Map<String, DataType> allowedKeys() {
                        return Map.of("configs", DataType.ARRAY);
                    }

                    @Override
                    public Object[] params() {
                        return params;
                    }

                    @Override
                    public Settings settings() {
                        return securityApiDependencies.settings();
                    }
                });
            }
        };
    }
}
