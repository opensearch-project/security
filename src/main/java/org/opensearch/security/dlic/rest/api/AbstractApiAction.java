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
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
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
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.forbiddenMessage;
import static org.opensearch.security.dlic.rest.api.Responses.notFoundMessage;
import static org.opensearch.security.dlic.rest.api.Responses.payload;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;

public abstract class AbstractApiAction extends BaseRestHandler {

    private final static Logger LOGGER = LogManager.getLogger(AbstractApiAction.class);

    protected final ConfigurationRepository cl;
    protected final ClusterService cs;
    final ThreadPool threadPool;
    protected String securityIndexName;
    private final RestApiPrivilegesEvaluator restApiPrivilegesEvaluator;
    protected final RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator;
    protected final AuditLog auditLog;
    protected final Settings settings;

    private Map<Method, RequestHandler> requestHandlers;

    protected final RequestHandler.RequestHandlersBuilder requestHandlersBuilder;

    protected AbstractApiAction(
        final Settings settings,
        final Path configPath,
        final RestController controller,
        final Client client,
        final AdminDNs adminDNs,
        final ConfigurationRepository cl,
        final ClusterService cs,
        final PrincipalExtractor principalExtractor,
        final PrivilegesEvaluator evaluator,
        ThreadPool threadPool,
        AuditLog auditLog
    ) {
        super();
        this.settings = settings;
        this.securityIndexName = settings.get(
            ConfigConstants.SECURITY_CONFIG_INDEX_NAME,
            ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX
        );

        this.cl = cl;
        this.cs = cs;
        this.threadPool = threadPool;
        this.restApiPrivilegesEvaluator = new RestApiPrivilegesEvaluator(
            settings,
            adminDNs,
            evaluator,
            principalExtractor,
            configPath,
            threadPool
        );
        this.restApiAdminPrivilegesEvaluator = new RestApiAdminPrivilegesEvaluator(
            threadPool.getThreadContext(),
            evaluator,
            adminDNs,
            settings.getAsBoolean(SECURITY_RESTAPI_ADMIN_ENABLED, false)
        );
        this.auditLog = auditLog;
        this.requestHandlersBuilder = new RequestHandler.RequestHandlersBuilder();
        this.requestHandlersBuilder.configureRequestHandlers(this::buildDefaultRequestHandlers);
    }

    private void buildDefaultRequestHandlers(final RequestHandler.RequestHandlersBuilder builder) {
        builder.withAccessHandler(request -> isSuperAdmin())
            .withSaveOrUpdateConfigurationHandler(this::saveOrUpdateConfiguration)
            .add(Method.POST, methodNotImplementedHandler)
            .onGetRequest(this::processGetRequest)
            .onChangeRequest(Method.DELETE, this::processDeleteRequest)
            .onChangeRequest(Method.PUT, this::processPutRequest);
    }

    protected final ValidationResult<SecurityConfiguration> processDeleteRequest(final RestRequest request) throws IOException {
        return withRequiredResourceName(request).map(name -> loadSecurityConfiguration(name, false))
            .map(this::resourceExists)
            .map(this::resourceCanBeChanged);
    }

    protected final ValidationResult<SecurityConfiguration> processGetRequest(final RestRequest request) throws IOException {
        return loadFilteredConfiguration(nameParam(request)).map(this::resourceExists);
    }

    protected final ValidationResult<SecurityConfiguration> processPutRequest(final RestRequest request) throws IOException {
        return withRequiredResourceName(request).map(name -> loadSecurityConfigurationWithRequestContent(name, request))
            .map(this::resourceCanBeChanged);
    }

    final void saveOrUpdateConfiguration(
        final Client client,
        final SecurityDynamicConfiguration<?> configuration,
        final OnSucessActionListener<IndexResponse> onSucessActionListener
    ) {
        saveAndUpdateConfigs(this.securityIndexName, client, getConfigName(), configuration, onSucessActionListener);
    }

    protected final String nameParam(final RestRequest request) {
        final String name = request.param("name");
        if (Strings.isNullOrEmpty(name)) {
            return null;
        }
        return name;
    }

    protected final ValidationResult<String> withRequiredResourceName(final RestRequest request) {
        final var resourceName = nameParam(request);
        if (resourceName == null) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("No " + getResourceName() + " specified."));
        }
        return ValidationResult.success(resourceName);
    }

    protected final ValidationResult<SecurityConfiguration> loadFilteredConfiguration(final String resourceName) throws IOException {
        return loadSecurityConfiguration(resourceName, true).map(this::resourceNotHidden).map(securityConfiguration -> {
            final var configuration = securityConfiguration.configuration();
            if (!isSuperAdmin()) {
                configuration.removeHidden();
            }
            configuration.clearHashes();
            configuration.set_meta(null);
            return ValidationResult.success(securityConfiguration);
        });
    }

    protected final ValidationResult<SecurityConfiguration> loadSecurityConfigurationWithRequestContent(
        final String resourceName,
        final RestRequest request
    ) throws IOException {
        return createValidator().validate(request)
            .map(
                content -> loadConfiguration(getConfigName(), false).map(
                    configuration -> ValidationResult.success(SecurityConfiguration.of(resourceName, content, configuration))
                )
            );
    }

    protected final ValidationResult<SecurityConfiguration> loadSecurityConfiguration(
        final String resourceName,
        final boolean logComplianceEvent
    ) throws IOException {
        return loadConfiguration(getConfigName(), logComplianceEvent).map(
            configuration -> ValidationResult.success(SecurityConfiguration.of(resourceName, configuration))
        );
    }

    protected final ValidationResult<SecurityDynamicConfiguration<?>> loadConfiguration(
        final CType cType,
        final boolean logComplianceEvent
    ) {
        final var configuration = load(cType, logComplianceEvent);
        if (configuration.getSeqNo() < 0) {
            return ValidationResult.error(
                RestStatus.FORBIDDEN,
                forbiddenMessage(
                    "Security index need to be updated to support '" + getConfigName().toLCString() + "'. Use SecurityAdmin to populate."
                )
            );
        }
        return ValidationResult.success(configuration);
    }

    protected final ValidationResult<SecurityConfiguration> resourceExists(final SecurityConfiguration securityConfiguration) {
        return resourceExists(getResourceName(), securityConfiguration);
    }

    protected final ValidationResult<SecurityConfiguration> resourceExists(
        final String resourceName,
        final SecurityConfiguration securityConfiguration
    ) {
        if (securityConfiguration.maybeResourceName().isPresent()) {
            if (!securityConfiguration.resourceExists()) {
                return ValidationResult.error(
                    RestStatus.NOT_FOUND,
                    notFoundMessage(resourceName + " '" + securityConfiguration.resourceName() + "' not found.")
                );
            }
            return ValidationResult.success(securityConfiguration);
        }
        return ValidationResult.success(securityConfiguration);
    }

    protected final ValidationResult<SecurityConfiguration> resourceCanBeChanged(final SecurityConfiguration securityConfiguration)
        throws IOException {
        return resourceNotHidden(securityConfiguration).map(ignore -> resourceNotReadOnly(securityConfiguration));
    }

    protected final ValidationResult<Pair<User, TransportAddress>> withUserAndRemoteAddress() {
        final var userAndRemoteAddress = Utils.userAndRemoteAddressFrom(threadPool.getThreadContext());
        if (userAndRemoteAddress.getLeft() == null) {
            return ValidationResult.error(RestStatus.UNAUTHORIZED, payload(RestStatus.UNAUTHORIZED, "Unauthorized"));
        }
        return ValidationResult.success(userAndRemoteAddress);
    }

    protected final ValidationResult<SecurityConfiguration> canChangeObjectWithRestAdminPermissions(
        final SecurityConfiguration securityConfiguration
    ) throws IOException {
        if (securityConfiguration.resourceExists()) {
            final var configuration = securityConfiguration.configuration();
            final var existingActionGroup = configuration.getCEntry(securityConfiguration.resourceName());
            if (restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(existingActionGroup)) {
                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
            }
        } else {
            final var reducedRequestContent = securityConfiguration.contentAsConfigObject();
            if (restApiAdminPrivilegesEvaluator.containsRestApiAdminPermissions(reducedRequestContent)) {
                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Access denied"));
            }
        }
        return ValidationResult.success(securityConfiguration);
    }

    protected final ValidationResult<SecurityConfiguration> validateRoles(
        final SecurityConfiguration securityConfiguration,
        final List<String> roles
    ) throws IOException {
        return loadConfiguration(CType.ROLES, false).map(rolesConfiguration -> {
            if (roles != null) {
                final var maybeNotValidRole = roles.stream().map(role -> {
                    try {
                        return resourceExists("role", SecurityConfiguration.of(role, rolesConfiguration)).map(this::resourceCanBeChanged);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                }).filter(Predicate.not(ValidationResult::isValid)).findFirst();
                if (maybeNotValidRole.isPresent()) {
                    return maybeNotValidRole.get();
                }
            }
            return ValidationResult.success(securityConfiguration);
        });
    }

    protected abstract RequestContentValidator createValidator(final Object... params);

    protected abstract String getResourceName();

    protected abstract CType getConfigName();

    protected void handleApiRequest(final RestChannel channel, final RestRequest request, final Client client) throws IOException {
        final var handlers = Optional.ofNullable(requestHandlers).orElseGet(requestHandlersBuilder::build);
        try {
            switch (request.method()) {
                case DELETE:
                    handlers.get(Method.DELETE).handle(channel, request, client);
                    break;
                case POST:
                    handlers.get(Method.POST).handle(channel, request, client);
                    break;
                case PUT:
                    handlers.get(Method.PUT).handle(channel, request, client);
                    break;
                case GET:
                    handlers.get(Method.GET).handle(channel, request, client);
                    break;
                default:
                    throw new IllegalArgumentException(request.method() + " not supported");
            }
        } catch (JsonMappingException jme) {
            throw jme;
            // TODO strip source
            // if(jme.getLocation() == null || jme.getLocation().getSourceRef() == null) {
            // throw jme;
            // } else throw new JsonMappingException(null, jme.getMessage());
        }
    }

    protected boolean hasPermissionsToCreate(
        final SecurityDynamicConfiguration<?> dynamicConfigFactory,
        final Object content,
        final String resourceName
    ) throws IOException {
        return false;
    }

    protected final SecurityDynamicConfiguration<?> load(final CType config, boolean logComplianceEvent) {
        SecurityDynamicConfiguration<?> loaded = cl.getConfigurationsFromIndex(Collections.singleton(config), logComplianceEvent)
            .get(config)
            .deepClone();
        return DynamicConfigFactory.addStatics(loaded);
    }

    protected boolean ensureIndexExists() {
        if (!cs.state().metadata().hasConcreteIndex(this.securityIndexName)) {
            return false;
        }
        return true;
    }

    protected void filter(SecurityDynamicConfiguration<?> builder) {
        if (!isSuperAdmin()) {
            builder.removeHidden();
        }
        builder.set_meta(null);
    }

    protected boolean isReadonlyFieldUpdated(final JsonNode existingResource, final JsonNode targetResource) {
        // Default is false. Override function for additional logic
        return false;
    }

    protected boolean isReadonlyFieldUpdated(final SecurityDynamicConfiguration<?> configuration, final JsonNode targetResource) {
        // Default is false. Override function for additional logic
        return false;
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
                Responses.conflict(channel, e.getMessage());
            } else {
                Responses.internalSeverError(channel, "Error " + e.getMessage());
            }
        }

    }

    public static void saveAndUpdateConfigs(
        final String indexName,
        final Client client,
        final CType cType,
        final SecurityDynamicConfiguration<?> configuration,
        final ActionListener<IndexResponse> actionListener
    ) {
        final IndexRequest ir = new IndexRequest(indexName);
        final String id = cType.toLCString();

        configuration.removeStatic();

        try {
            client.index(
                ir.id(id)
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .setIfSeqNo(configuration.getSeqNo())
                    .setIfPrimaryTerm(configuration.getPrimaryTerm())
                    .source(id, XContentHelper.toXContent(configuration, XContentType.JSON, false)),
                new ConfigUpdatingActionListener<>(new String[] { id }, client, actionListener)
            );
        } catch (IOException e) {
            throw ExceptionsHelper.convertToOpenSearchException(e);
        }
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
            return channel -> internalErrorResponse(channel, RequestContentValidator.ValidationError.SECURITY_NOT_INITIALIZED.message());
        }

        // check if request is authorized
        String authError = restApiPrivilegesEvaluator.checkAccessPermissions(request, getEndpoint());

        final User user = (User) threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        final String userName = user == null ? null : user.getName();
        if (authError != null) {
            LOGGER.error("No permission to access REST API: " + authError);
            auditLog.logMissingPrivileges(authError, userName, request);
            // for rest request
            request.params().clear();
            return channel -> forbidden(channel, "No permission to access REST API: " + authError);
        } else {
            auditLog.logGrantedPrivileges(userName, request);
        }

        final Object originalUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        final Object originalRemoteAddress = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        final Object originalOrigin = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN);

        return channel -> threadPool.generic().submit(() -> {
            try (StoredContext ignore = threadPool.getThreadContext().stashContext()) {
                threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
                threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, originalUser);
                threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, originalRemoteAddress);
                threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, originalOrigin);

                handleApiRequest(channel, request, client);
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

    protected static XContentBuilder convertToJson(RestChannel channel, ToXContent toxContent) {
        try {
            XContentBuilder builder = channel.newBuilder();
            toxContent.toXContent(builder, ToXContent.EMPTY_PARAMS);
            return builder;
        } catch (IOException e) {
            throw ExceptionsHelper.convertToOpenSearchException(e);
        }
    }

    protected void response(RestChannel channel, RestStatus status, String message) {
        try {
            final XContentBuilder builder = channel.newBuilder();
            builder.startObject();
            builder.field("status", status.name());
            builder.field("message", message);
            builder.endObject();
            channel.sendResponse(new BytesRestResponse(status, builder));
        } catch (IOException e) {
            throw ExceptionsHelper.convertToOpenSearchException(e);
        }
    }

    protected void successResponse(RestChannel channel, SecurityDynamicConfiguration<?> response) {
        channel.sendResponse(new BytesRestResponse(RestStatus.OK, convertToJson(channel, response)));
    }

    protected void successResponse(RestChannel channel) {
        try {
            final XContentBuilder builder = channel.newBuilder();
            builder.startObject();
            builder.endObject();
            channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));
        } catch (IOException e) {
            internalErrorResponse(channel, "Unable to fetch license: " + e.getMessage());
            LOGGER.error("Cannot fetch convert license to XContent due to", e);
        }
    }

    protected void badRequestResponse(RestChannel channel, ToXContent validationResult) {
        channel.sendResponse(new BytesRestResponse(RestStatus.BAD_REQUEST, convertToJson(channel, validationResult)));
    }

    protected void successResponse(RestChannel channel, String message) {
        response(channel, RestStatus.OK, message);
    }

    protected void createdResponse(RestChannel channel, String message) {
        response(channel, RestStatus.CREATED, message);
    }

    protected void badRequestResponse(RestChannel channel, String message) {
        response(channel, RestStatus.BAD_REQUEST, message);
    }

    protected void notFound(RestChannel channel, String message) {
        response(channel, RestStatus.NOT_FOUND, message);
    }

    protected void forbidden(RestChannel channel, String message) {
        response(channel, RestStatus.FORBIDDEN, message);
    }

    protected void internalErrorResponse(RestChannel channel, String message) {
        response(channel, RestStatus.INTERNAL_SERVER_ERROR, message);
    }

    protected void conflict(RestChannel channel, String message) {
        response(channel, RestStatus.CONFLICT, message);
    }

    protected void notImplemented(RestChannel channel, Method method) {
        response(channel, RestStatus.NOT_IMPLEMENTED, "Method " + method.name() + " not supported for this action.");
    }

    protected final ValidationResult<SecurityConfiguration> resourceNotHidden(final SecurityConfiguration securityConfiguration) {
        if (isHidden(securityConfiguration.configuration(), securityConfiguration.resourceName())) {
            return ValidationResult.error(
                RestStatus.NOT_FOUND,
                notFoundMessage("Resource '" + securityConfiguration.resourceName() + "' is not available.")
            );
        }
        return ValidationResult.success(securityConfiguration);
    }

    protected final ValidationResult<SecurityConfiguration> resourceNotReadOnly(final SecurityConfiguration securityConfiguration) {
        if (isReadOnly(securityConfiguration.configuration(), securityConfiguration.resourceName())) {
            return ValidationResult.error(
                RestStatus.FORBIDDEN,
                forbiddenMessage("Resource '" + securityConfiguration.resourceName() + "' is read-only.")
            );
        }
        return ValidationResult.success(securityConfiguration);
    }

    protected final boolean isReserved(SecurityDynamicConfiguration<?> configuration, String resourceName) {
        return configuration.isStatic(resourceName) || configuration.isReserved(resourceName);
    }

    protected final boolean isHidden(SecurityDynamicConfiguration<?> configuration, String resourceName) {
        return configuration.isHidden(resourceName) && !isSuperAdmin();
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

    protected abstract Endpoint getEndpoint();

    protected boolean isSuperAdmin() {
        return restApiAdminPrivilegesEvaluator.isCurrentUserRestApiAdminFor(getEndpoint());
    }

    /**
     * Resource is readonly if it is reserved and user is not super admin.
     * @param existingConfiguration Configuration
     * @param name
     * @return True if resource readonly
     */
    protected boolean isReadOnly(final SecurityDynamicConfiguration<?> existingConfiguration, String name) {
        return !isSuperAdmin() && isReserved(existingConfiguration, name);
    }

    /**
     * Checks if it is valid to add role to opendistro_security_roles or rolesmapping.
     * Role can be mapped to user if it exists. Only superadmin can add hidden or reserved roles.
     *
     * @param channel	Rest Channel for response
     * @param role		Name of the role
     * @return True if role can be mapped
     */
    protected boolean isValidRolesMapping(final RestChannel channel, final String role) {
        final SecurityDynamicConfiguration<?> rolesConfiguration = load(CType.ROLES, false);
        final SecurityDynamicConfiguration<?> rolesMappingConfiguration = load(CType.ROLESMAPPING, false);

        if (!rolesConfiguration.exists(role)) {
            notFound(channel, "Role '" + role + "' is not available for role-mapping.");
            return false;
        }

        if (isHidden(rolesConfiguration, role)) {
            notFound(channel, "Role '" + role + "' is not available for role-mapping.");
            return false;
        }

        return isWriteable(channel, rolesMappingConfiguration, role);
    }

    boolean isWriteable(final RestChannel channel, final SecurityDynamicConfiguration<?> configuration, final String resourceName) {
        if (isHidden(configuration, resourceName)) {
            notFound(channel, "Resource '" + resourceName + "' is not available.");
            return false;
        }

        if (isReadOnly(configuration, resourceName)) {
            forbidden(channel, "Resource '" + resourceName + "' is read-only.");
            return false;
        }
        return true;
    }
}
