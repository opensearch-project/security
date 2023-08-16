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

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.Strings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.Hashed;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.security.user.UserService;
import org.opensearch.security.user.UserServiceException;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.opensearch.security.dlic.rest.api.Responses.badRequest;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.methodNotImplementedMessage;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.payload;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static org.opensearch.security.dlic.rest.support.Utils.hash;

public class InternalUsersApiAction extends AbstractApiAction {

    protected final static String RESOURCE_NAME = "user";

    static final List<String> RESTRICTED_FROM_USERNAME = ImmutableList.of(
        ":" // Not allowed in basic auth, see https://stackoverflow.com/a/33391003/533057
    );

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new Route(Method.GET, "/user/{name}"),
            new Route(Method.GET, "/user/"),
            new Route(Method.POST, "/user/{name}/authtoken"),
            new Route(Method.DELETE, "/user/{name}"),
            new Route(Method.PUT, "/user/{name}"),

            // corrected mapping, introduced in OpenSearch Security
            new Route(Method.GET, "/internalusers/{name}"),
            new Route(Method.GET, "/internalusers/"),
            new Route(Method.POST, "/internalusers/{name}/authtoken"),
            new Route(Method.DELETE, "/internalusers/{name}"),
            new Route(Method.PUT, "/internalusers/{name}"),
            new Route(Method.PATCH, "/internalusers/"),
            new Route(Method.PATCH, "/internalusers/{name}")
        )
    );

    UserService userService;

    @Inject
    public InternalUsersApiAction(
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
        UserService userService,
        AuditLog auditLog
    ) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
        this.userService = userService;
        this.requestHandlersBuilder.configureRequestHandlers(this::internalUsersApiRequestHandlers);
    }

    @Override
    protected boolean hasPermissionsToCreate(
        final SecurityDynamicConfiguration<?> dynamicConfigFactory,
        final Object content,
        final String resourceName
    ) {
        return true;
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.INTERNALUSERS;
    }

    @Override
    protected String getResourceName() {
        return RESOURCE_NAME;
    }

    @Override
    protected CType getConfigType() {
        return CType.INTERNALUSERS;
    }

    private void internalUsersApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        // spotless:off
        requestHandlersBuilder
                // Overrides the GET request functionality to allow for the special case of requesting an auth token.
                .override(Method.POST, (channel, request, client) ->
                        withAuthTokenPath(request)
                                .map(username ->
                                        loadConfiguration(getConfigType(), true, false)
                                                .map(configuration -> ValidationResult.success(SecurityConfiguration.of(username, configuration)))
                                )
                                .map(endpointValidator::entityExists)
                                .valid(securityConfiguration -> generateAuthToken(channel, securityConfiguration))
                                .error((status, toXContent) -> Responses.response(channel, status, toXContent)))
                .onChangeRequest(Method.PATCH, this::processPatchRequest)
                .onChangeRequest(Method.PUT, request ->
                        withRequiredResourceName(request)
                                .map(username -> loadConfigurationWithRequestContent(username, request, endpointValidator.createRequestContentValidator()))
                                .map(endpointValidator::hasRightsToChangeEntity)
                                .map(this::validateSecurityRoles)
                                .map(securityConfiguration -> createOrUpdateAccount(request, securityConfiguration))
                                .map(this::validateAndUpdatePassword)
                                .map(this::addEntityToConfig)
        );
        // spotless:on
    }

    private ValidationResult<String> withAuthTokenPath(final RestRequest request) throws IOException {
        return withRequiredResourceName(request).map(username -> {
            // Handle auth token fetching
            if (!(request.uri().contains("/internalusers/" + username + "/authtoken") && request.uri().endsWith("/authtoken"))) {
                return ValidationResult.error(RestStatus.NOT_IMPLEMENTED, methodNotImplementedMessage(request.method()));
            }
            return ValidationResult.success(username);
        });
    }

    private void generateAuthToken(final RestChannel channel, final SecurityConfiguration securityConfiguration) throws IOException {
        try {
            final var username = securityConfiguration.entityName();
            final var authToken = userService.generateAuthToken(username);
            if (!Strings.isNullOrEmpty(authToken)) {
                ok(channel, "'" + username + "' authtoken generated " + authToken);
            } else {
                badRequest(channel, "'" + username + "' authtoken failed to be created.");
            }
        } catch (final UserServiceException e) {
            badRequest(channel, e.getMessage());
        }
    }

    private ValidationResult<SecurityConfiguration> validateSecurityRoles(final SecurityConfiguration securityConfiguration)
        throws IOException {
        return loadConfiguration(CType.ROLES, false, false).map(rolesConfiguration -> {
            final ObjectNode contentAsNode = (ObjectNode) securityConfiguration.requestContent();
            final SecurityJsonNode securityJsonNode = new SecurityJsonNode(contentAsNode);
            // FIXME do we need to verify roles as well?
            final var securityRoles = securityJsonNode.get("opendistro_security_roles").asList();
            return endpointValidator.validateRoles(securityRoles, rolesConfiguration)
                .map(ignore -> ValidationResult.success(securityConfiguration));
        });
    }

    private ValidationResult<SecurityConfiguration> createOrUpdateAccount(
        final RestRequest request,
        final SecurityConfiguration securityConfiguration
    ) throws IOException {
        try {
            final var username = securityConfiguration.entityName();
            final var content = (ObjectNode) securityConfiguration.requestContent();
            if (request.hasParam("service")) {
                content.put("service", request.param("service"));
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

    private ValidationResult<SecurityConfiguration> validateAndUpdatePassword(final SecurityConfiguration securityConfiguration) {
        // when updating an existing user password hash can be blank, which means no changes
        // for existing users, hash is optional
        final var username = securityConfiguration.entityName();
        final ObjectNode contentAsNode = (ObjectNode) securityConfiguration.requestContent();
        final SecurityJsonNode securityJsonNode = new SecurityJsonNode(contentAsNode);
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
            public String resourceName() {
                return RESOURCE_NAME;
            }

            @Override
            public Endpoint endpoint() {
                return getEndpoint();
            }

            @Override
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return restApiAdminPrivilegesEvaluator;
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
                    content.put("hash", hash(plainTextPassword.toCharArray()));
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
                        return settings;
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
