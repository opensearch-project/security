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

import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.core.JsonPointer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.CheckedSupplier;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentHelper;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.filter.SecurityRequestFactory;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import com.flipkart.zjsonpatch.JsonPatch;
import com.flipkart.zjsonpatch.JsonPatchApplicationException;

import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.conflict;
import static org.opensearch.security.dlic.rest.api.Responses.forbidden;
import static org.opensearch.security.dlic.rest.api.Responses.forbiddenMessage;
import static org.opensearch.security.dlic.rest.api.Responses.internalServerError;
import static org.opensearch.security.dlic.rest.api.Responses.payload;
import static org.opensearch.security.dlic.rest.support.Utils.withIOException;

public abstract class AbstractApiAction extends BaseRestHandler {

    private final static Logger LOGGER = LogManager.getLogger(AbstractApiAction.class);

    private final static Set<String> supportedPatchOperations = Set.of("add", "replace", "remove");

    private final static String supportedPatchOperationsAsString = String.join(",", supportedPatchOperations);

    protected final ClusterService clusterService;

    protected final ThreadPool threadPool;

    private Map<Method, RequestHandler> requestHandlers;

    protected final RequestHandler.RequestHandlersBuilder requestHandlersBuilder;

    protected final EndpointValidator endpointValidator;

    protected final Endpoint endpoint;

    protected final SecurityApiDependencies securityApiDependencies;

    protected AbstractApiAction(
        final Endpoint endpoint,
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super();
        this.endpoint = endpoint;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.securityApiDependencies = securityApiDependencies;
        this.requestHandlersBuilder = new RequestHandler.RequestHandlersBuilder();
        this.requestHandlersBuilder.configureRequestHandlers(this::buildDefaultRequestHandlers);
        this.endpointValidator = createEndpointValidator();
    }

    private void buildDefaultRequestHandlers(final RequestHandler.RequestHandlersBuilder builder) {
        builder.withAccessHandler(request -> securityApiDependencies.restApiAdminPrivilegesEvaluator().isCurrentUserAdminFor(endpoint))
            .withSaveOrUpdateConfigurationHandler(this::saveOrUpdateConfiguration)
            .add(Method.POST, methodNotImplementedHandler)
            .add(Method.PATCH, methodNotImplementedHandler)
            .onGetRequest(this::processGetRequest)
            .onChangeRequest(Method.DELETE, this::processDeleteRequest)
            .onChangeRequest(Method.PUT, this::processPutRequest);
    }

    protected final ValidationResult<SecurityConfiguration> processDeleteRequest(final RestRequest request) throws IOException {
        return endpointValidator.withRequiredEntityName(nameParam(request))
            .map(entityName -> loadConfiguration(entityName, false))
            .map(endpointValidator::onConfigDelete)
            .map(this::removeEntityFromConfig);
    }

    protected final ValidationResult<SecurityConfiguration> removeEntityFromConfig(final SecurityConfiguration securityConfiguration) {
        final var configuration = securityConfiguration.configuration();
        configuration.remove(securityConfiguration.entityName());
        return ValidationResult.success(securityConfiguration);
    }

    protected final ValidationResult<SecurityConfiguration> processGetRequest(final RestRequest request) throws IOException {
        return loadConfiguration(getConfigType(), true, true).map(
            configuration -> ValidationResult.success(SecurityConfiguration.of(nameParam(request), configuration))
        ).map(endpointValidator::onConfigLoad).map(securityConfiguration -> securityConfiguration.maybeEntityName().map(entityName -> {
            securityConfiguration.configuration().removeOthers(entityName);
            return ValidationResult.success(securityConfiguration);
        }).orElse(ValidationResult.success(securityConfiguration)));
    }

    /**
     * Process patch requests for all types of configuration, which can be one entity in the URI or a list of entities in the request body.
     **/
    protected final ValidationResult<SecurityConfiguration> processPatchRequest(final RestRequest request) throws IOException {
        return loadConfiguration(nameParam(request), false).map(
            securityConfiguration -> withPatchRequestContent(request).map(
                patchContent -> securityConfiguration.maybeEntityName()
                    .map(entityName -> patchEntity(request, patchContent, securityConfiguration))
                    .orElseGet(() -> patchEntities(request, patchContent, securityConfiguration))
            )
        );
    }

    protected final ValidationResult<JsonNode> withPatchRequestContent(final RestRequest request) {
        try {
            final var parsedPatchRequestContent = Utils.toJsonNode(request.content().utf8ToString());
            if (!(parsedPatchRequestContent instanceof ArrayNode)) {
                return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("Wrong request body"));
            }
            final var operations = patchOperations(parsedPatchRequestContent);
            if (operations.isEmpty()) {
                return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("Wrong request body"));
            }
            for (final var patchOperation : operations) {
                if (!supportedPatchOperations.contains(patchOperation)) {
                    return ValidationResult.error(
                        RestStatus.BAD_REQUEST,
                        badRequestMessage(
                            "Unsupported patch operation: " + patchOperation + ". Supported are: " + supportedPatchOperationsAsString
                        )
                    );
                }
            }
            return ValidationResult.success(parsedPatchRequestContent);
        } catch (final IOException e) {
            LOGGER.debug("Error while parsing JSON patch", e);
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("Error in JSON patch: " + e.getMessage()));
        }
    }

    protected final ValidationResult<SecurityConfiguration> patchEntity(
        final RestRequest request,
        final JsonNode patchContent,
        final SecurityConfiguration securityConfiguration
    ) {
        final var entityName = securityConfiguration.entityName();
        final var configuration = securityConfiguration.configuration();
        return withIOException(
            () -> endpointValidator.isAllowedToChangeImmutableEntity(securityConfiguration)
                .map(endpointValidator::entityExists)
                .map(ignore -> {
                    final var configurationAsJson = (ObjectNode) Utils.convertJsonToJackson(configuration, true);
                    final var entityAsJson = (ObjectNode) configurationAsJson.get(entityName);
                    return withJsonPatchException(
                        () -> endpointValidator.createRequestContentValidator(entityName)
                            .validate(request, JsonPatch.apply(patchContent, entityAsJson))
                            .map(
                                patchedEntity -> endpointValidator.onConfigChange(
                                    SecurityConfiguration.of(patchedEntity, entityName, configuration)
                                ).map(sc -> ValidationResult.success(patchedEntity))
                            )
                            .map(patchedEntity -> {
                                final var updatedConfigurationAsJson = configurationAsJson.deepCopy().set(entityName, patchedEntity);
                                return ValidationResult.success(
                                    SecurityConfiguration.of(
                                        entityName,
                                        SecurityDynamicConfiguration.fromNode(
                                            updatedConfigurationAsJson,
                                            configuration.getCType(),
                                            configuration.getVersion(),
                                            configuration.getSeqNo(),
                                            configuration.getPrimaryTerm()
                                        )
                                    )
                                );
                            })
                    );
                })
        );
    }

    protected ValidationResult<SecurityConfiguration> patchEntities(
        final RestRequest request,
        final JsonNode patchContent,
        final SecurityConfiguration securityConfiguration
    ) {
        final var configuration = securityConfiguration.configuration();
        final var configurationAsJson = (ObjectNode) Utils.convertJsonToJackson(configuration, true);
        return withIOException(() -> withJsonPatchException(() -> {
            final var patchedConfigurationAsJson = JsonPatch.apply(patchContent, configurationAsJson);
            for (final var entityName : patchEntityNames(patchContent)) {
                final var beforePatchEntity = configurationAsJson.get(entityName);
                final var patchedEntity = patchedConfigurationAsJson.get(entityName);
                // verify we can process existing or updated entities
                if (beforePatchEntity != null && !Objects.equals(beforePatchEntity, patchedEntity)) {
                    final var checkEntityCanBeProcess = endpointValidator.isAllowedToChangeImmutableEntity(
                        SecurityConfiguration.of(entityName, configuration)
                    );
                    if (!checkEntityCanBeProcess.isValid()) {
                        return checkEntityCanBeProcess;
                    }
                }
                // entity removed no need to process patched content
                if (patchedEntity == null) {
                    continue;
                }
                // create or update case of the entity. we need to verify new JSON configuration for them
                if ((beforePatchEntity == null) || !Objects.equals(beforePatchEntity, patchedEntity)) {
                    final var requestCheck = endpointValidator.createRequestContentValidator(entityName).validate(request, patchedEntity);
                    if (!requestCheck.isValid()) {
                        return ValidationResult.error(requestCheck.status(), requestCheck.errorMessage());
                    }
                }
                // verify new JSON content for each entity using same set of validator we use for PUT, PATCH and DELETE
                final var additionalValidatorCheck = endpointValidator.onConfigChange(
                    SecurityConfiguration.of(patchedEntity, entityName, configuration)
                );
                if (!additionalValidatorCheck.isValid()) {
                    return additionalValidatorCheck;
                }
            }
            return ValidationResult.success(
                SecurityConfiguration.of(
                    null,// there is no entity name in case of patch, since there could be more the one diff entity within configuration
                    SecurityDynamicConfiguration.fromNode(
                        patchedConfigurationAsJson,
                        configuration.getCType(),
                        configuration.getVersion(),
                        configuration.getSeqNo(),
                        configuration.getPrimaryTerm()
                    )
                )
            );
        }));
    }

    private ValidationResult<SecurityConfiguration> withJsonPatchException(
        final CheckedSupplier<ValidationResult<SecurityConfiguration>, IOException> action
    ) throws IOException {
        try {
            return action.get();
        } catch (final JsonPatchApplicationException e) {
            LOGGER.debug("Error while applying JSON patch", e);
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(e.getMessage()));
        }
    }

    protected final Set<String> patchOperations(final JsonNode patchRequestContent) {
        final var operations = ImmutableSet.<String>builder();
        for (final JsonNode node : patchRequestContent) {
            if (node.has("op")) operations.add(node.get("op").asText());
        }
        return operations.build();
    }

    protected final Set<String> patchEntityNames(final JsonNode patchRequestContent) {
        final var patchedResourceNames = ImmutableSet.<String>builder();
        for (final JsonNode node : patchRequestContent) {
            if (node.has("path")) {
                final var s = JsonPointer.compile(node.get("path").asText());
                patchedResourceNames.add(s.getMatchingProperty());
            }
        }
        return patchedResourceNames.build();
    }

    protected final ValidationResult<SecurityConfiguration> processPutRequest(final RestRequest request) throws IOException {
        return processPutRequest(nameParam(request), request);
    }

    protected final ValidationResult<SecurityConfiguration> processPutRequest(final String entityName, final RestRequest request)
        throws IOException {
        return endpointValidator.withRequiredEntityName(entityName)
            .map(ignore -> loadConfigurationWithRequestContent(entityName, request))
            .map(endpointValidator::onConfigChange)
            .map(this::addEntityToConfig);
    }

    protected final ValidationResult<SecurityConfiguration> addEntityToConfig(final SecurityConfiguration securityConfiguration)
        throws IOException {
        final var configuration = securityConfiguration.configuration();
        final var entityObjectConfig = Utils.toConfigObject(securityConfiguration.requestContent(), configuration.getImplementingClass());
        configuration.putCObject(securityConfiguration.entityName(), entityObjectConfig);
        return ValidationResult.success(securityConfiguration);
    }

    final void saveOrUpdateConfiguration(
        final Client client,
        final SecurityDynamicConfiguration<?> configuration,
        final OnSucessActionListener<IndexResponse> onSucessActionListener
    ) {
        saveAndUpdateConfigsAsync(securityApiDependencies, client, getConfigType(), configuration, onSucessActionListener);
    }

    protected final String nameParam(final RestRequest request) {
        final String name = request.param("name");
        if (Strings.isNullOrEmpty(name)) {
            return null;
        }
        return name;
    }

    protected final ValidationResult<SecurityConfiguration> loadConfigurationWithRequestContent(
        final String entityName,
        final RestRequest request
    ) throws IOException {
        return endpointValidator.createRequestContentValidator()
            .validate(request)
            .map(
                content -> loadConfiguration(getConfigType(), false, false).map(
                    configuration -> ValidationResult.success(SecurityConfiguration.of(content, entityName, configuration))
                )
            );
    }

    protected final ValidationResult<SecurityConfiguration> loadConfiguration(final String entityName, final boolean logComplianceEvent)
        throws IOException {
        return loadConfiguration(getConfigType(), false, logComplianceEvent).map(
            configuration -> ValidationResult.success(SecurityConfiguration.of(entityName, configuration))
        );
    }

    protected ValidationResult<SecurityDynamicConfiguration<?>> loadConfiguration(
        final CType cType,
        boolean omitSensitiveData,
        final boolean logComplianceEvent
    ) {
        SecurityDynamicConfiguration<?> configuration;
        if (omitSensitiveData) {
            configuration = loadAndRedact(cType, logComplianceEvent);
        } else {
            configuration = load(cType, logComplianceEvent);
        }
        if (configuration.getSeqNo() < 0) {

            return ValidationResult.error(
                RestStatus.FORBIDDEN,
                forbiddenMessage(
                    "Security index need to be updated to support '" + getConfigType().toLCString() + "'. Use SecurityAdmin to populate."
                )
            );
        }
        if (omitSensitiveData) {
            if (!securityApiDependencies.restApiAdminPrivilegesEvaluator().isCurrentUserAdminFor(endpoint)) {
                configuration.removeHidden();
            }
            configuration.clearHashes();
            configuration.set_meta(null);
        }
        return ValidationResult.success(configuration);
    }

    protected final ValidationResult<Pair<User, TransportAddress>> withUserAndRemoteAddress() {
        final var userAndRemoteAddress = Utils.userAndRemoteAddressFrom(threadPool.getThreadContext());
        if (userAndRemoteAddress.getLeft() == null) {
            return ValidationResult.error(RestStatus.UNAUTHORIZED, payload(RestStatus.UNAUTHORIZED, "Unauthorized"));
        }
        return ValidationResult.success(userAndRemoteAddress);
    }

    protected EndpointValidator createEndpointValidator() {
        // Pessimistic Validator. All CRUD actions are forbidden
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
            public ValidationResult<SecurityConfiguration> onConfigDelete(SecurityConfiguration securityConfiguration) throws IOException {

                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigLoad(SecurityConfiguration securityConfiguration) throws IOException {

                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigChange(SecurityConfiguration securityConfiguration) throws IOException {

                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return RequestContentValidator.NOOP_VALIDATOR;
            }
        };
    }

    protected abstract CType getConfigType();

    protected final SecurityDynamicConfiguration<?> load(final CType config, boolean logComplianceEvent) {
        SecurityDynamicConfiguration<?> loaded = securityApiDependencies.configurationRepository()
            .getConfigurationsFromIndex(List.of(config), logComplianceEvent)
            .get(config)
            .deepClone();
        return DynamicConfigFactory.addStatics(loaded);
    }

    protected final SecurityDynamicConfiguration<?> loadAndRedact(final CType config, boolean logComplianceEvent) {
        SecurityDynamicConfiguration<?> loaded = securityApiDependencies.configurationRepository()
            .getConfigurationsFromIndex(List.of(config), logComplianceEvent)
            .get(config)
            .deepCloneWithRedaction();
        return DynamicConfigFactory.addStatics(loaded);
    }

    protected boolean ensureIndexExists() {
        return clusterService.state().metadata().hasConcreteIndex(securityApiDependencies.securityIndexName());
    }

    abstract static class OnSucessActionListener<Response> implements ActionListener<Response> {

        private final RestChannel channel;

        public OnSucessActionListener(RestChannel channel) {
            super();
            this.channel = channel;
        }

        @Override
        public final void onFailure(Exception e) {
            if (ExceptionsHelper.unwrapCause(e) instanceof VersionConflictEngineException) {
                conflict(channel, e.getMessage());
            } else {
                internalServerError(channel, "Error " + e.getMessage());
            }
        }

    }

    public static ActionFuture<IndexResponse> saveAndUpdateConfigs(
        final SecurityApiDependencies dependencies,
        final Client client,
        final CType cType,
        final SecurityDynamicConfiguration<?> configuration
    ) {
        final var request = createIndexRequestForConfig(dependencies, cType, configuration);
        return client.index(request);
    }

    public static void saveAndUpdateConfigsAsync(
        final SecurityApiDependencies dependencies,
        final Client client,
        final CType cType,
        final SecurityDynamicConfiguration<?> configuration,
        final ActionListener<IndexResponse> actionListener
    ) {
        final var ir = createIndexRequestForConfig(dependencies, cType, configuration);
        client.index(ir, new ConfigUpdatingActionListener<>(new String[] { cType.toLCString() }, client, actionListener));
    }

    private static IndexRequest createIndexRequestForConfig(
        final SecurityApiDependencies dependencies,
        final CType cType,
        final SecurityDynamicConfiguration<?> configuration
    ) {
        configuration.removeStatic();
        final BytesReference content;
        try {
            content = XContentHelper.toXContent(configuration, XContentType.JSON, ToXContent.EMPTY_PARAMS, false);
        } catch (final IOException e) {
            throw ExceptionsHelper.convertToOpenSearchException(e);
        }

        return new IndexRequest(dependencies.securityIndexName()).id(cType.toLCString())
            .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .setIfSeqNo(configuration.getSeqNo())
            .setIfPrimaryTerm(configuration.getPrimaryTerm())
            .source(cType.toLCString(), content);
    }

    protected static class ConfigUpdatingActionListener<Response> implements ActionListener<Response> {
        private final String[] cTypes;
        private final Client client;
        private final ActionListener<Response> delegate;

        public ConfigUpdatingActionListener(String[] cTypes, Client client, ActionListener<Response> delegate) {
            this.cTypes = Objects.requireNonNull(cTypes, "cTypes must not be null");
            this.client = Objects.requireNonNull(client, "client must not be null");
            this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        }

        @Override
        public void onResponse(Response response) {

            final ConfigUpdateRequest cur = new ConfigUpdateRequest(cTypes);

            client.execute(ConfigUpdateAction.INSTANCE, cur, new ActionListener<ConfigUpdateResponse>() {
                @Override
                public void onResponse(final ConfigUpdateResponse ur) {
                    if (ur.hasFailures()) {
                        delegate.onFailure(ur.failures().get(0));
                        return;
                    }
                    delegate.onResponse(response);
                }

                @Override
                public void onFailure(final Exception e) {
                    delegate.onFailure(e);
                }
            });

        }

        @Override
        public void onFailure(Exception e) {
            delegate.onFailure(e);
        }

    }

    @Override
    protected final RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        // consume all parameters first so we can return a correct HTTP status,
        // not 400
        consumeParameters(request);

        // check if .opendistro_security index has been initialized
        if (!ensureIndexExists()) {
            return channel -> internalServerError(channel, RequestContentValidator.ValidationError.SECURITY_NOT_INITIALIZED.message());
        }

        // check if request is authorized
        final String authError = securityApiDependencies.restApiPrivilegesEvaluator().checkAccessPermissions(request, endpoint);

        final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        final String userName = user == null ? null : user.getName();
        if (authError != null) {
            LOGGER.error("No permission to access REST API: " + authError);
            securityApiDependencies.auditLog().logMissingPrivileges(authError, userName, SecurityRequestFactory.from(request));
            // for rest request
            request.params().clear();
            return channel -> forbidden(channel, "No permission to access REST API: " + authError);
        } else {
            securityApiDependencies.auditLog().logGrantedPrivileges(userName, SecurityRequestFactory.from(request));
        }

        final var originalUserAndRemoteAddress = Utils.userAndRemoteAddressFrom(threadPool.getThreadContext());
        final Object originalOrigin = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN);

        return channel -> threadPool.generic().submit(() -> {
            try (StoredContext ignore = threadPool.getThreadContext().stashContext()) {
                threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
                threadPool.getThreadContext()
                    .putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, originalUserAndRemoteAddress.getLeft());
                threadPool.getThreadContext()
                    .putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, originalUserAndRemoteAddress.getRight());
                threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, originalOrigin);

                requestHandlers = Optional.ofNullable(requestHandlers).orElseGet(requestHandlersBuilder::build);
                final var requestHandler = requestHandlers.getOrDefault(request.method(), methodNotImplementedHandler);
                requestHandler.handle(channel, request, client);
            } catch (Exception e) {
                LOGGER.error("Error processing request {}", request, e);
                try {
                    channel.sendResponse(new BytesRestResponse(channel, e));
                } catch (IOException ioe) {
                    throw ExceptionsHelper.convertToOpenSearchException(e);
                }
            }
        });
    }

    /**
     * Consume all defined parameters for the request. Before we handle the
     * request in subclasses where we actually need the parameter, some global
     * checks are performed, e.g. check whether the .security_index index exists. Thus, the
     * parameter(s) have not been consumed, and OpenSearch will always return a 400 with
     * an internal error message.
     *
     * @param request
     */
    protected void consumeParameters(final RestRequest request) {
        request.param("name");
    }

    @Override
    public String getName() {
        return getClass().getSimpleName();
    }

}
