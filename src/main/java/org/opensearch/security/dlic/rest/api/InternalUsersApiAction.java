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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
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
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
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

import static org.opensearch.security.dlic.rest.api.Responses.badRequest;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.methodNotImplementedMessage;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.payload;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static org.opensearch.security.dlic.rest.support.Utils.hash;

public class InternalUsersApiAction extends PatchableResourceApiAction {
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
        return "user";
    }

    @Override
    protected CType getConfigName() {
        return CType.INTERNALUSERS;
    }

    @Override
    protected void configureRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        // spotless:off
        // Overrides the GET request functionality to allow for the special case of requesting an auth token.
        requestHandlersBuilder
                .override(Method.POST, (channel, request, client) ->
                        withAuthTokenPath(request)
                                .map(this::loadFilteredConfiguration)
                                .map(this::resourceExists)
                                .valid(securityConfiguration -> generateAuthToken(channel, securityConfiguration))
                                .error((status, toXContent) -> Responses.response(channel, status, toXContent)))
                .onChangeRequest(Method.PUT, request ->
                        processPutRequest(request)
                                .map(securityConfiguration -> createOrUpdateUser(request, securityConfiguration))
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
            final var username = securityConfiguration.resourceName();
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

    private ValidationResult<SecurityConfiguration> createOrUpdateUser(
        final RestRequest request,
        final SecurityConfiguration securityConfiguration
    ) throws IOException {
        final var username = securityConfiguration.resourceName();
        final ObjectNode contentAsNode = (ObjectNode) securityConfiguration.requestContent();
        final SecurityJsonNode securityJsonNode = new SecurityJsonNode(contentAsNode);
        // FIXME do we need to verify roles as well?
        final var securityRoles = securityJsonNode.get("opendistro_security_roles").asList();
        // Don't allow user to add non-existent role or a role for which role-mapping is hidden or reserved
        // spotless:off
        return validateRoles(securityConfiguration, securityRoles)
                .map(ignore -> createOrUpdateAccount(request, securityConfiguration))
                .map(updatedSecurityConfiguration -> {
                    // when updating an existing user password hash can be blank, which means no changes
                    // for existing users, hash is optional
                    if (updatedSecurityConfiguration.resourceExists() && securityJsonNode.get("hash").asString() == null) {
                        final String hash = ((Hashed) updatedSecurityConfiguration.configuration().getCEntry(username)).getHash();
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
                    return ValidationResult.success(updatedSecurityConfiguration);
                });
        // spotless:on
    }

    private ValidationResult<SecurityConfiguration> createOrUpdateAccount(
        final RestRequest request,
        final SecurityConfiguration securityConfiguration
    ) throws IOException {
        try {
            final var username = securityConfiguration.resourceName();
            final var content = securityConfiguration.requestContent();
            if (request.hasParam("service")) {
                ((ObjectNode) content).put("service", request.param("service"));
            }
            if (request.hasParam("enabled")) {
                ((ObjectNode) content).put("enabled", request.param("enabled"));
            }
            ((ObjectNode) content).put("name", username);
            // FIXME add better solution for account and internal users
            final var updateConfiguration = userService.createOrUpdateAccount((ObjectNode) content);
            // remove extra user in case we deal with the new one. not nice better to redesign account users.
            if (!securityConfiguration.resourceExists()) updateConfiguration.remove(securityConfiguration.resourceName());
            return ValidationResult.success(SecurityConfiguration.of(username, content, updateConfiguration));
        } catch (UserServiceException ex) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(ex.getMessage()));
        }
    }

    @Override
    protected ValidationResult<JsonNode> postProcessApplyPatchResult(
        RestChannel channel,
        RestRequest request,
        JsonNode existingResourceAsJsonNode,
        JsonNode updatedResourceAsJsonNode,
        String resourceName
    ) throws IOException {
        RequestContentValidator retVal = null;
        JsonNode passwordNode = updatedResourceAsJsonNode.get("password");
        if (passwordNode != null) {
            String plainTextPassword = passwordNode.asText();
            final JsonNode passwordObject = DefaultObjectMapper.objectMapper.createObjectNode().put("password", plainTextPassword);
            final ValidationResult<JsonNode> validationResult = createValidator(resourceName).validate(request, passwordObject);
            ((ObjectNode) updatedResourceAsJsonNode).remove("password");
            ((ObjectNode) updatedResourceAsJsonNode).set("hash", new TextNode(hash(plainTextPassword.toCharArray())));
            return validationResult;
        }
        return null;
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
            public Map<String, RequestContentValidator.DataType> allowedKeys() {
                final ImmutableMap.Builder<String, DataType> allowedKeys = ImmutableMap.builder();
                if (isSuperAdmin()) {
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
}
