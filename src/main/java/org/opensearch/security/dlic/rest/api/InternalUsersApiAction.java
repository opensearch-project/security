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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.FieldConfiguration;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.securityconf.Hashed;
import org.opensearch.security.securityconf.RoleMappings;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.security.user.UserFilterType;
import org.opensearch.security.user.UserService;
import org.opensearch.security.user.UserServiceException;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import tools.jackson.databind.node.ObjectNode;

import static org.opensearch.security.dlic.rest.api.Responses.badRequest;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.conflict;
import static org.opensearch.security.dlic.rest.api.Responses.conflictMessage;
import static org.opensearch.security.dlic.rest.api.Responses.forbiddenMessage;
import static org.opensearch.security.dlic.rest.api.Responses.internalServerError;
import static org.opensearch.security.dlic.rest.api.Responses.methodNotImplementedMessage;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.payload;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.OPENDISTRO_API_DEPRECATION_MESSAGE;
import static org.opensearch.security.dlic.rest.support.Utils.addLegacyRoutesPrefix;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class InternalUsersApiAction extends AbstractApiAction {

    private static final Logger LOGGER = LogManager.getLogger(InternalUsersApiAction.class);

    private final PasswordHasher passwordHasher;

    @Override
    protected void consumeParameters(final RestRequest request) {
        super.consumeParameters(request);
        request.param("filterBy");
    }

    public static final List<String> RESTRICTED_FROM_USERNAME = ImmutableList.of(
        ":" // Not allowed in basic auth, see https://stackoverflow.com/a/33391003/533057
    );

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new Route(Method.GET, "/user/{name}"),
            new Route(Method.GET, "/user"),
            new Route(Method.POST, "/user/{name}/authtoken"),
            new Route(Method.DELETE, "/user/{name}"),
            new Route(Method.PUT, "/user/{name}"),

            // corrected mapping, introduced in OpenSearch Security
            new Route(Method.GET, "/internalusers/{name}"),
            new Route(Method.GET, "/internalusers"),
            new Route(Method.POST, "/internalusers/{name}/authtoken"),
            new Route(Method.POST, "/internalusers/{name}/_rename"),
            new Route(Method.DELETE, "/internalusers/{name}"),
            new Route(Method.PUT, "/internalusers/{name}"),
            new Route(Method.PATCH, "/internalusers"),
            new Route(Method.PATCH, "/internalusers/{name}")
        )
    );

    private static final List<DeprecatedRoute> deprecatedRoutes = addLegacyRoutesPrefix(
        ImmutableList.of(
            new DeprecatedRoute(Method.GET, "/user/{name}", OPENDISTRO_API_DEPRECATION_MESSAGE),
            new DeprecatedRoute(Method.GET, "/user", OPENDISTRO_API_DEPRECATION_MESSAGE),
            new DeprecatedRoute(Method.POST, "/user/{name}/authtoken", OPENDISTRO_API_DEPRECATION_MESSAGE),
            new DeprecatedRoute(Method.DELETE, "/user/{name}", OPENDISTRO_API_DEPRECATION_MESSAGE),
            new DeprecatedRoute(Method.PUT, "/user/{name}", OPENDISTRO_API_DEPRECATION_MESSAGE),

            // corrected mapping, introduced in OpenSearch Security
            new DeprecatedRoute(Method.GET, "/internalusers/{name}", OPENDISTRO_API_DEPRECATION_MESSAGE),
            new DeprecatedRoute(Method.GET, "/internalusers", OPENDISTRO_API_DEPRECATION_MESSAGE),
            new DeprecatedRoute(Method.POST, "/internalusers/{name}/authtoken", OPENDISTRO_API_DEPRECATION_MESSAGE),
            new DeprecatedRoute(Method.DELETE, "/internalusers/{name}", OPENDISTRO_API_DEPRECATION_MESSAGE),
            new DeprecatedRoute(Method.PUT, "/internalusers/{name}", OPENDISTRO_API_DEPRECATION_MESSAGE),
            new DeprecatedRoute(Method.PATCH, "/internalusers", OPENDISTRO_API_DEPRECATION_MESSAGE),
            new DeprecatedRoute(Method.PATCH, "/internalusers/{name}", OPENDISTRO_API_DEPRECATION_MESSAGE)
        )
    );

    UserService userService;

    @Inject
    public InternalUsersApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final UserService userService,
        final SecurityApiDependencies securityApiDependencies,
        final PasswordHasher passwordHasher
    ) {
        super(Endpoint.INTERNALUSERS, clusterService, threadPool, securityApiDependencies);
        this.userService = userService;
        this.requestHandlersBuilder.configureRequestHandlers(this::internalUsersApiRequestHandlers);
        this.passwordHasher = passwordHasher;
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    public List<DeprecatedRoute> deprecatedRoutes() {
        return deprecatedRoutes;
    }

    @Override
    protected CType<?> getConfigType() {
        return CType.INTERNALUSERS;
    }

    @Override
    protected boolean supportsAsync() {
        return true;
    }

    private void internalUsersApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.onGetRequest(
            request -> ValidationResult.success(request).map(this::processGetRequest).map(securityConfiguration -> {
                final var configuration = securityConfiguration.configuration();
                filterUsers(configuration, filterParam(request));
                return ValidationResult.success(securityConfiguration);
            })
        )
            // Overrides the GET request functionality to allow for the special case of requesting an auth token.
            .override(Method.POST, (channel, request, client) -> {
                if (isRenameRequest(request)) {
                    handleRenameRequest(channel, request, client);
                    return;
                }
                withAuthTokenPath(request).map(
                    username -> loadConfiguration(getConfigType(), true, false).map(
                        configuration -> ValidationResult.success(SecurityConfiguration.of(username, configuration))
                    )
                )
                    .map(endpointValidator::entityExists)
                    .map(endpointValidator::isAllowedToLoadOrChangeHiddenEntity)
                    .valid(securityConfiguration -> generateAuthToken(channel, securityConfiguration))
                    .error((status, toXContent) -> response(channel, status, toXContent));
            })
            .onChangeRequest(Method.PATCH, this::processPatchRequest)
            .onChangeRequest(
                Method.PUT,
                request -> endpointValidator.withRequiredEntityName(nameParam(request))
                    .map(username -> loadConfigurationWithRequestContent(username, request))
                    .map(endpointValidator::isAllowedToChangeImmutableEntity)
                    .map(this::validateSecurityRoles)
                    .map(securityConfiguration -> createOrUpdateAccount(request, securityConfiguration))
                    .map(this::validateAndUpdatePassword)
                    .map(this::addEntityToConfig)
            )
            .withPaginatedGetRequest(this::routeGetRequest);

    }

    @Override
    protected void postLoadForPagination(final RestRequest request, final SecurityDynamicConfiguration<?> configuration) {
        userService.includeAccountsIfType(configuration, filterParam(request));
    }

    protected final ValidationResult<SecurityConfiguration> filterUsers(SecurityDynamicConfiguration<?> users, UserFilterType userType) {
        userService.includeAccountsIfType(users, userType);
        return ValidationResult.success(SecurityConfiguration.of(users.getCType().toString(), users));

    }

    protected final UserFilterType filterParam(final RestRequest request) {
        final String filter = request.param("filterBy");
        if (Strings.isNullOrEmpty(filter)) {
            return UserFilterType.ANY;
        }
        return UserFilterType.fromString(filter);
    }

    ValidationResult<String> withAuthTokenPath(final RestRequest request) throws IOException {
        return endpointValidator.withRequiredEntityName(nameParam(request)).map(username -> {
            // Handle auth token fetching
            if (request.uri().contains("/internalusers/" + username + "/authtoken") && request.uri().endsWith("/authtoken")) {
                return ValidationResult.success(username);
            }
            return ValidationResult.error(RestStatus.NOT_IMPLEMENTED, methodNotImplementedMessage(request.method()));
        });
    }

    void generateAuthToken(final RestChannel channel, final SecurityConfiguration securityConfiguration) throws IOException {
        try {
            final var username = securityConfiguration.entityName();
            final var authToken = userService.generateAuthToken(username);
            ok(channel, "'" + username + "' authtoken generated " + authToken);
        } catch (final UserServiceException e) {
            badRequest(channel, e.getMessage());
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Rename: POST /_plugins/_security/api/internalusers/{name}/_rename {"new_username": "..."}
    //
    // A rename changes two documents in the security index: "internalusers" (the user record) and
    // "rolesmapping" (explicit "users" references). OpenSearch has no multi-document transaction, so:
    // 1. Plan: read both documents, validate everything and build the new versions in memory.
    // 2. Write internalusers, then rolesmapping. Each write is guarded by the _seq_no we read, so a
    // concurrent change by another admin fails with 409 instead of being silently overwritten.
    // 3. If the rolesmapping write fails, write the original internalusers document back (undo).
    // 4. Reload both config types on every node.
    // internalusers is written first so that the worst case (undo also fails) leaves the renamed
    // user with fewer permissions, not more.
    // ---------------------------------------------------------------------------------------------

    static final String NEW_USERNAME_FIELD = "new_username";

    /** Everything a rename needs, computed and validated before anything is written. */
    record RenamePlan(String oldUsername, String newUsername, SecurityDynamicConfiguration<?> originalInternalUsers,
        SecurityDynamicConfiguration<?> renamedInternalUsers, SecurityDynamicConfiguration<?> updatedRolesMapping, List<
            String> updatedRoleMappings) {
    }

    boolean isRenameRequest(final RestRequest request) {
        return request.path().endsWith("/_rename");
    }

    void handleRenameRequest(final RestChannel channel, final RestRequest request, final Client client) throws IOException {
        endpointValidator.withRequiredEntityName(nameParam(request))
            .map(oldUsername -> renameRequestContentValidator().validate(request).map(content -> {
                final String newUsername = content.get(NEW_USERNAME_FIELD).asText();
                return loadConfiguration(CType.INTERNALUSERS, false, false).map(
                    internalUsers -> loadConfiguration(CType.ROLESMAPPING, false, false).map(
                        rolesMapping -> planRename(oldUsername, newUsername, internalUsers, rolesMapping)
                    )
                );
            }))
            .valid(plan -> executeRename(channel, client, plan))
            .error((status, toXContent) -> response(channel, status, toXContent));
    }

    private RequestContentValidator renameRequestContentValidator() {
        return RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
            @Override
            public Object[] params() {
                return new Object[0];
            }

            @Override
            public Settings settings() {
                return securityApiDependencies.settings();
            }

            @Override
            public Set<String> mandatoryKeys() {
                return Set.of(NEW_USERNAME_FIELD);
            }

            @Override
            public Map<String, FieldConfiguration> allowedKeys() {
                return Map.of(NEW_USERNAME_FIELD, FieldConfiguration.of(DataType.STRING));
            }
        });
    }

    /** Step 1: validate and compute the new documents. Pure in-memory work; any error here means nothing was written. */
    ValidationResult<RenamePlan> planRename(
        final String oldUsername,
        final String newUsername,
        final SecurityDynamicConfiguration<?> internalUsers,
        final SecurityDynamicConfiguration<?> rolesMapping
    ) throws IOException {
        // Validate the new name with the same rules as user creation.
        final var newNameValid = endpointValidator.withRequiredEntityName(Strings.isNullOrEmpty(newUsername) ? null : newUsername);
        if (!newNameValid.isValid()) {
            return ValidationResult.error(newNameValid.status(), newNameValid.errorMessage());
        }
        final var restricted = UserService.restrictedFromUsername(newUsername);
        if (restricted.isPresent()) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(restricted.get()));
        }
        if (newUsername.equals(oldUsername)) {
            return ValidationResult.error(
                RestStatus.BAD_REQUEST,
                badRequestMessage("'new_username' must differ from the current username.")
            );
        }

        // Source user must exist and be changeable by the caller (hidden/reserved users need admin rights).
        final var source = endpointValidator.entityExists(SecurityConfiguration.of(oldUsername, internalUsers))
            .map(endpointValidator::isAllowedToLoadOrChangeHiddenEntity)
            .map(endpointValidator::isAllowedToChangeImmutableEntity);
        if (!source.isValid()) {
            return ValidationResult.error(source.status(), source.errorMessage());
        }
        // Static users come from code, not the security index, so they cannot be renamed by anyone.
        if (internalUsers.isStatic(oldUsername)) {
            return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Resource '" + oldUsername + "' is static."));
        }

        // Destination must be free.
        if (internalUsers.exists(newUsername)) {
            return ValidationResult.error(RestStatus.CONFLICT, conflictMessage("User '" + newUsername + "' already exists."));
        }

        // Rewrite explicit "users" references in role mappings. Wildcard patterns (e.g. "ali*") are left untouched.
        final var updatedRolesMapping = rolesMapping.deepClone();
        final List<String> updatedRoleMappings = new ArrayList<>();
        for (final var entry : updatedRolesMapping.getCEntries().entrySet()) {
            final var mapping = (RoleMappings) entry.getValue();
            if (!mapping.getUsers().contains(oldUsername)) {
                continue;
            }
            final var mappingChangeable = endpointValidator.isAllowedToChangeImmutableEntity(
                SecurityConfiguration.of(entry.getKey(), updatedRolesMapping)
            );
            if (!mappingChangeable.isValid()) {
                return ValidationResult.error(mappingChangeable.status(), mappingChangeable.errorMessage());
            }
            final List<String> users = new ArrayList<>();
            for (final String user : mapping.getUsers()) {
                final String replacement = user.equals(oldUsername) ? newUsername : user;
                if (!users.contains(replacement)) {
                    users.add(replacement);
                }
            }
            mapping.setUsers(users);
            updatedRoleMappings.add(entry.getKey());
        }
        Collections.sort(updatedRoleMappings);

        final var renamedInternalUsers = internalUsers.deepClone();
        moveEntry(renamedInternalUsers, oldUsername, newUsername);

        return ValidationResult.success(
            new RenamePlan(oldUsername, newUsername, internalUsers, renamedInternalUsers, updatedRolesMapping, updatedRoleMappings)
        );
    }

    private static <T> void moveEntry(final SecurityDynamicConfiguration<T> configuration, final String from, final String to) {
        final T entry = configuration.getCEntry(from);
        configuration.remove(from);
        configuration.putCEntry(to, entry);
    }

    /** Steps 2-4: write internalusers, then rolesmapping (undoing the first write if the second fails), then reload. */
    void executeRename(final RestChannel channel, final Client client, final RenamePlan plan) {
        final var usersWrite = createIndexRequestForConfig(securityApiDependencies, CType.INTERNALUSERS, plan.renamedInternalUsers());
        client.index(usersWrite, new ActionListener<>() {
            @Override
            public void onResponse(final IndexResponse usersWriteResponse) {
                if (plan.updatedRoleMappings().isEmpty()) {
                    reloadAndRespond(channel, client, plan, usersWriteResponse, CType.INTERNALUSERS);
                    return;
                }
                final var mappingsWrite = createIndexRequestForConfig(
                    securityApiDependencies,
                    CType.ROLESMAPPING,
                    plan.updatedRolesMapping()
                );
                client.index(mappingsWrite, new ActionListener<>() {
                    @Override
                    public void onResponse(final IndexResponse mappingsWriteResponse) {
                        reloadAndRespond(channel, client, plan, mappingsWriteResponse, CType.INTERNALUSERS, CType.ROLESMAPPING);
                    }

                    @Override
                    public void onFailure(final Exception mappingsWriteFailure) {
                        undoInternalUsersWrite(channel, client, plan, usersWriteResponse, mappingsWriteFailure);
                    }
                });
            }

            @Override
            public void onFailure(final Exception usersWriteFailure) {
                // Nothing was written.
                respondWithWriteFailure(channel, plan, usersWriteFailure);
            }
        });
    }

    private void undoInternalUsersWrite(
        final RestChannel channel,
        final Client client,
        final RenamePlan plan,
        final IndexResponse usersWriteResponse,
        final Exception mappingsWriteFailure
    ) {
        // Restore the original document, guarded by the _seq_no of our own write so we never overwrite
        // a change another admin made in the meantime.
        final var original = plan.originalInternalUsers();
        original.setSeqNo(usersWriteResponse.getSeqNo());
        original.setPrimaryTerm(usersWriteResponse.getPrimaryTerm());
        client.index(createIndexRequestForConfig(securityApiDependencies, CType.INTERNALUSERS, original), new ActionListener<>() {
            @Override
            public void onResponse(final IndexResponse undoResponse) {
                // Reload so no node keeps the intermediate state, then report the original failure.
                new ConfigUpdatingActionListener<IndexResponse>(
                    new String[] { CType.INTERNALUSERS.toLCString() },
                    client,
                    new ActionListener<IndexResponse>() {
                        @Override
                        public void onResponse(final IndexResponse ignored) {
                            respondWithWriteFailure(channel, plan, mappingsWriteFailure);
                        }

                        @Override
                        public void onFailure(final Exception e) {
                            respondWithWriteFailure(channel, plan, mappingsWriteFailure);
                        }
                    }
                ).onResponse(undoResponse);
            }

            @Override
            public void onFailure(final Exception undoFailure) {
                LOGGER.error(
                    "Rename of internal user '{}' to '{}' was partially applied: the user was renamed but role mappings were not "
                        + "updated, and restoring the original user failed. Role mappings that still reference '{}': {}",
                    plan.oldUsername(),
                    plan.newUsername(),
                    plan.oldUsername(),
                    plan.updatedRoleMappings(),
                    undoFailure
                );
                internalServerError(
                    channel,
                    "Rename partially applied: user '"
                        + plan.oldUsername()
                        + "' was renamed to '"
                        + plan.newUsername()
                        + "' but role mappings "
                        + plan.updatedRoleMappings()
                        + " were not updated. Update them manually."
                );
            }
        });
    }

    private void reloadAndRespond(
        final RestChannel channel,
        final Client client,
        final RenamePlan plan,
        final IndexResponse lastWrite,
        final CType<?>... changedTypes
    ) {
        final String[] types = Arrays.stream(changedTypes).map(CType::toLCString).toArray(String[]::new);
        new ConfigUpdatingActionListener<>(types, client, new OnSucessActionListener<IndexResponse>(channel) {
            @Override
            public void onResponse(final IndexResponse ignored) {
                ok(
                    channel,
                    (builder, params) -> builder.startObject()
                        .field("status", RestStatus.OK.name())
                        .field("message", "'" + plan.oldUsername() + "' renamed to '" + plan.newUsername() + "'.")
                        .field("previous_username", plan.oldUsername())
                        .field("username", plan.newUsername())
                        .field("updated_roles_mapping", plan.updatedRoleMappings())
                        .endObject()
                );
            }
        }).onResponse(lastWrite);
    }

    private void respondWithWriteFailure(final RestChannel channel, final RenamePlan plan, final Exception e) {
        if (ExceptionsHelper.unwrapCause(e) instanceof VersionConflictEngineException) {
            conflict(
                channel,
                "Security configuration was modified concurrently; '" + plan.oldUsername() + "' was not renamed. Retry the request."
            );
        } else {
            LOGGER.error("Failed to rename internal user '{}' to '{}'", plan.oldUsername(), plan.newUsername(), e);
            internalServerError(channel, "Failed to rename '" + plan.oldUsername() + "': " + e.getMessage());
        }
    }

    ValidationResult<SecurityConfiguration> validateSecurityRoles(final SecurityConfiguration securityConfiguration) throws IOException {
        // check here that all roles are not hidden and all mappings are mutable (not static, reserved or hidden)
        return loadConfiguration(CType.ROLES, false, false).map(
            rolesConfiguration -> loadConfiguration(CType.ROLESMAPPING, false, false).map(roleMappingsConfiguration -> {
                final var contentAsNode = (ObjectNode) securityConfiguration.requestContent();
                final var securityJsonNode = new SecurityJsonNode(contentAsNode);
                var securityRoles = securityJsonNode.get("opendistro_security_roles").asList();
                securityRoles = securityRoles == null ? List.of() : securityRoles;
                final var rolesValid = endpointValidator.validateRoles(securityRoles, rolesConfiguration);
                if (!rolesValid.isValid()) {
                    return ValidationResult.error(rolesValid.status(), rolesValid.errorMessage());
                }
                for (final var role : securityRoles) {
                    final var roleMappingValid = endpointValidator.isAllowedToChangeImmutableEntity(
                        SecurityConfiguration.of(role, roleMappingsConfiguration)
                    );
                    if (!roleMappingValid.isValid()) {
                        return ValidationResult.error(roleMappingValid.status(), roleMappingValid.errorMessage());
                    }
                }
                return ValidationResult.success(securityConfiguration);
            })
        );
    }

    ValidationResult<SecurityConfiguration> createOrUpdateAccount(
        final RestRequest request,
        final SecurityConfiguration securityConfiguration
    ) throws IOException {
        try {
            final var username = securityConfiguration.entityName();
            final var content = (ObjectNode) securityConfiguration.requestContent();
            if (request.hasParam("attributes")) {
                content.put("attributes", request.param("attributes"));
            }
            if (request.hasParam("enabled")) {
                content.put("enabled", request.param("enabled"));
            }
            content.put("name", username);
            // FIXME add better solution for account and internal users
            final var updateConfiguration = userService.createOrUpdateAccount(content);
            // remove extra user in case we deal with the new one. not nice better to redesign account users.
            if (!securityConfiguration.entityExists()) updateConfiguration.remove(securityConfiguration.entityName());
            return ValidationResult.success(SecurityConfiguration.of(content, username, updateConfiguration));
        } catch (UserServiceException ex) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(ex.getMessage()));
        }
    }

    ValidationResult<SecurityConfiguration> validateAndUpdatePassword(final SecurityConfiguration securityConfiguration) {
        // when updating an existing user password hash can be blank, which means no changes
        // for existing users, hash is optional
        final var username = securityConfiguration.entityName();
        final var contentAsNode = (ObjectNode) securityConfiguration.requestContent();
        final var securityJsonNode = new SecurityJsonNode(contentAsNode);
        if (securityConfiguration.entityExists() && securityJsonNode.get("hash").asString() == null) {
            final String hash = ((Hashed) securityConfiguration.configuration().getCEntry(username)).getHash();
            if (Strings.isNullOrEmpty(hash)) {
                return ValidationResult.error(
                    RestStatus.INTERNAL_SERVER_ERROR,
                    payload(
                        RestStatus.INTERNAL_SERVER_ERROR,
                        "Existing user " + username + " has no password, and no new password or hash was specified."
                    )
                );
            }
            contentAsNode.put("hash", hash);
        }
        return ValidationResult.success(securityConfiguration);
    }

    @Override
    protected EndpointValidator createEndpointValidator() {
        return new EndpointValidator() {
            @Override
            public Endpoint endpoint() {
                return endpoint;
            }

            @Override
            public RestApiAuthorizationEvaluator restApiAuthorizationEvaluator() {
                return securityApiDependencies.restApiAuthorizationEvaluator();
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigChange(SecurityConfiguration securityConfiguration) throws IOException {
                // this method will be called only for PATCH
                return EndpointValidator.super.onConfigChange(securityConfiguration).map(this::validateUserName)
                    .map(this::generateHashForPassword)
                    .map(InternalUsersApiAction.this::validateAndUpdatePassword)
                    .map(InternalUsersApiAction.this::validateSecurityRoles);
            }

            private ValidationResult<SecurityConfiguration> validateUserName(final SecurityConfiguration securityConfiguration) {
                return UserService.restrictedFromUsername(securityConfiguration.entityName())
                    .<ValidationResult<SecurityConfiguration>>map(m -> ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(m)))
                    .orElseGet(() -> ValidationResult.success(securityConfiguration));
            }

            private ValidationResult<SecurityConfiguration> generateHashForPassword(final SecurityConfiguration securityConfiguration) {
                final var content = (ObjectNode) securityConfiguration.requestContent();
                if (content.has("password")) {
                    final var plainTextPassword = content.get("password").asText();
                    content.remove("password");
                    content.put("hash", passwordHasher.hash(plainTextPassword.toCharArray()));
                }
                return ValidationResult.success(securityConfiguration);
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
                    public Map<String, RequestContentValidator.FieldConfiguration> allowedKeys() {
                        final ImmutableMap.Builder<String, FieldConfiguration> allowedKeys = ImmutableMap.builder();
                        if (isCurrentUserAdmin()) {
                            allowedKeys.put("hidden", FieldConfiguration.of(DataType.BOOLEAN));
                            allowedKeys.put("reserved", FieldConfiguration.of(DataType.BOOLEAN));
                        }
                        return allowedKeys.put("backend_roles", FieldConfiguration.of(DataType.ARRAY))
                            .put("attributes", FieldConfiguration.of(DataType.OBJECT))
                            .put("description", FieldConfiguration.of(DataType.STRING))
                            .put("opendistro_security_roles", FieldConfiguration.of(DataType.ARRAY))
                            .put("hash", FieldConfiguration.of(DataType.STRING))
                            .put("password", FieldConfiguration.of(DataType.STRING))
                            .build();
                    }
                });
            }
        };
    }

}
