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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.Strings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.securityconf.Hashed;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.security.user.UserFilterType;
import org.opensearch.security.user.UserService;
import org.opensearch.security.user.UserServiceException;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.Responses.badRequest;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.methodNotImplementedMessage;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.payload;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class InternalUsersApiAction extends AbstractApiAction {

    private final PasswordHasher passwordHasher;

    @Override
    protected void consumeParameters(final RestRequest request) {
        request.param("name");
        request.param("filterBy");
    }

    static final List<String> RESTRICTED_FROM_USERNAME = ImmutableList.of(
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
            new Route(Method.DELETE, "/internalusers/{name}"),
            new Route(Method.PUT, "/internalusers/{name}"),
            new Route(Method.PATCH, "/internalusers"),
            new Route(Method.PATCH, "/internalusers/{name}")
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
    protected CType getConfigType() {
        return CType.INTERNALUSERS;
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
            .override(
                Method.POST,
                (channel, request, client) -> withAuthTokenPath(request).map(
                    username -> loadConfiguration(getConfigType(), true, false).map(
                        configuration -> ValidationResult.success(SecurityConfiguration.of(username, configuration))
                    )
                )
                    .map(endpointValidator::entityExists)
                    .map(endpointValidator::isAllowedToLoadOrChangeHiddenEntity)
                    .valid(securityConfiguration -> generateAuthToken(channel, securityConfiguration))
                    .error((status, toXContent) -> response(channel, status, toXContent))
            )
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
            );

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
            if (!(request.uri().contains("/internalusers/" + username + "/authtoken") && request.uri().endsWith("/authtoken"))) {
                return ValidationResult.error(RestStatus.NOT_IMPLEMENTED, methodNotImplementedMessage(request.method()));
            }
            return ValidationResult.success(username);
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
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return securityApiDependencies.restApiAdminPrivilegesEvaluator();
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigChange(SecurityConfiguration securityConfiguration) throws IOException {
                // this method will be called only for PATCH
                return EndpointValidator.super.onConfigChange(securityConfiguration).map(this::generateHashForPassword);
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
                    public Map<String, RequestContentValidator.DataType> allowedKeys() {
                        final ImmutableMap.Builder<String, DataType> allowedKeys = ImmutableMap.builder();
                        if (isCurrentUserAdmin()) {
                            allowedKeys.put("reserved", DataType.BOOLEAN);
                        }
                        return allowedKeys.put("backend_roles", DataType.ARRAY)
                            .put("attributes", DataType.OBJECT)
                            .put("description", DataType.STRING)
                            .put("opendistro_security_roles", DataType.ARRAY)
                            .put("hash", DataType.STRING)
                            .put("password", DataType.STRING)
                            .build();
                    }
                });
            }
        };
    }

}
