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
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.api.RolesApiAction.RoleRequestContentValidator;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigHelper;
import org.opensearch.threadpool.ThreadPool;

import com.flipkart.zjsonpatch.DiffFlags;
import com.flipkart.zjsonpatch.JsonDiff;

import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static org.opensearch.security.dlic.rest.support.Utils.withIOException;

public class ConfigUpgradeApiAction extends AbstractApiAction {

    private final static Logger LOGGER = LogManager.getLogger(ConfigUpgradeApiAction.class);

    private final static Set<CType> SUPPORTED_CTYPES = ImmutableSet.of(CType.ROLES);

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(new Route(Method.GET, "/_upgrade_check"), new Route(Method.POST, "/_upgrade_perform"))
    );

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
        withIOException(() -> getAndValidateConfigurationsToUpgrade(request).map(this::configurationDifferences)).valid(differencesList -> {
            final var canUpgrade = differencesList.stream().anyMatch(entry -> entry.v2().size() > 0);

            final ObjectNode response = JsonNodeFactory.instance.objectNode();
            response.put("can_upgrade", canUpgrade);

            if (canUpgrade) {
                final ObjectNode differences = JsonNodeFactory.instance.objectNode();
                differencesList.forEach(t -> { differences.set(t.v1().toLCString(), t.v2()); });
                response.set("differences", differences);
            }
            channel.sendResponse(new BytesRestResponse(RestStatus.OK, XContentType.JSON.mediaType(), response.toPrettyString()));
        }).error((status, toXContent) -> response(channel, status, toXContent));
    }

    private void handleUpgrade(final RestChannel channel, final RestRequest request, final Client client) throws IOException {
        withIOException(() -> getAndValidateConfigurationsToUpgrade(request).map(this::configurationDifferences)).map(
            diffs -> applyDifferences(request, diffs)
        ).valid(updatedResources -> {
            ok(channel, "Applied all differences: " + updatedResources);
        }).error((status, toXContent) -> response(channel, status, toXContent));
    }

    ValidationResult<List<Tuple<CType, Map<String, List<String>>>>> applyDifferences(
        final RestRequest request,
        final List<Tuple<CType, JsonNode>> differencesToUpdate
    ) throws IOException {
        final var updatedResources = new ArrayList<ValidationResult<Tuple<CType, Map<String, List<String>>>>>();
        for (final Tuple<CType, JsonNode> difference : differencesToUpdate) {
            updatedResources.add(
                loadConfiguration(difference.v1(), false, false).map(
                    configuration -> patchEntities(request, difference.v2(), SecurityConfiguration.of(null, configuration)).map(
                        patchResults -> {
                            final var items = new HashMap<String, String>();
                            difference.v2().forEach(node -> {
                                final var item = pathRoot(node);
                                final var operation = node.get("op").asText();
                                if (items.containsKey(item) && !items.get(item).equals(operation)) {
                                    items.put(item, "modified");
                                } else {
                                    items.put(item, operation);
                                }
                            });

                            final var itemsGroupedByOperation = items.entrySet()
                                .stream()
                                .collect(
                                    Collectors.groupingBy(Map.Entry::getValue, Collectors.mapping(Map.Entry::getKey, Collectors.toList()))
                                );

                            return ValidationResult.success(new Tuple<>(difference.v1(), itemsGroupedByOperation));
                        }
                    )
                )
            );
        }

        return ValidationResult.merge(updatedResources);
    }

    private ValidationResult<List<Tuple<CType, JsonNode>>> configurationDifferences(final Set<CType> configurations) throws IOException {
        final var differences = new ArrayList<ValidationResult<Tuple<CType, JsonNode>>>();
        for (final var configuration : configurations) {
            differences.add(computeDifferenceToUpdate(configuration));
        }
        return ValidationResult.merge(differences);
    }

    private ValidationResult<Tuple<CType, JsonNode>> computeDifferenceToUpdate(final CType configType) throws IOException {
        return loadConfiguration(configType, false, false).map(activeRoles -> {
            final var activeRolesJson = Utils.convertJsonToJackson(activeRoles, false);
            final var defaultRolesJson = loadConfigFileAsJson(configType);
            final var rawDiff = JsonDiff.asJson(activeRolesJson, defaultRolesJson, EnumSet.of(DiffFlags.OMIT_VALUE_ON_REMOVE));
            return ValidationResult.success(new Tuple<>(configType, filterRemoveOperations(rawDiff)));
        });
    }

    private ValidationResult<Set<CType>> getAndValidateConfigurationsToUpgrade(final RestRequest request) {
        final String[] configs = request.paramAsStringArray("configs", null);

        final var configurations = Optional.ofNullable(configs).map(CType::fromStringValues).orElse(SUPPORTED_CTYPES);

        if (!configurations.stream().allMatch(SUPPORTED_CTYPES::contains)) {
            // Remove all supported configurations
            configurations.removeAll(SUPPORTED_CTYPES);
            return ValidationResult.error(
                RestStatus.BAD_REQUEST,
                badRequestMessage("Unsupported configurations for upgrade" + configurations)
            );
        }

        return ValidationResult.success(configurations);
    }

    JsonNode filterRemoveOperations(final JsonNode diff) {
        final ArrayNode filteredDiff = JsonNodeFactory.instance.arrayNode();
        diff.forEach(node -> {
            if (!isRemoveOperation(node)) {
                filteredDiff.add(node);
                return;
            } else {
                if (!hasRootLevelPath(node)) {
                    filteredDiff.add(node);
                }
            }
        });
        return filteredDiff;
    }

    private String pathRoot(final JsonNode node) {
        return node.get("path").asText().split("/")[1];
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
        throw new UnsupportedOperationException("This class supports multiple configuration types");
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
                return new RoleRequestContentValidator(new RequestContentValidator.ValidationContext() {
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
                        return Map.of("configs", DataType.ARRAY);
                    }
                });
            }
        };
    }

    public static class ConfigUpgradeContentValidator extends RequestContentValidator {

        protected ConfigUpgradeContentValidator(final ValidationContext validationContext) {
            super(validationContext);
        }

        @Override
        public ValidationResult<JsonNode> validate(RestRequest request) throws IOException {
            return super.validate(request);
        }

        @Override
        public ValidationResult<JsonNode> validate(RestRequest request, JsonNode jsonContent) throws IOException {
            return super.validate(request, jsonContent);
        }

    }

}
