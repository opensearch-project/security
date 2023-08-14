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
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
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
    protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content)
        throws IOException {

        final String username = request.param("name");

        SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getConfigName(), false);

        if (!isWriteable(channel, internalUsersConfiguration, username)) {
            return;
        }

        final ObjectNode contentAsNode = (ObjectNode) content;
        final SecurityJsonNode securityJsonNode = new SecurityJsonNode(contentAsNode);

        // Don't allow user to add non-existent role or a role for which role-mapping is hidden or reserved
        final List<String> securityRoles = securityJsonNode.get("opendistro_security_roles").asList();
        if (securityRoles != null) {
            for (final String role : securityRoles) {
                if (!isValidRolesMapping(channel, role)) {
                    return;
                }
            }
        }

        final boolean userExisted = internalUsersConfiguration.exists(username);

        // when updating an existing user password hash can be blank, which means no
        // changes

        try {
            if (request.hasParam("service")) {
                ((ObjectNode) content).put("service", request.param("service"));
            }
            if (request.hasParam("enabled")) {
                ((ObjectNode) content).put("enabled", request.param("enabled"));
            }
            ((ObjectNode) content).put("name", username);
            internalUsersConfiguration = userService.createOrUpdateAccount((ObjectNode) content);
        } catch (UserServiceException ex) {
            badRequestResponse(channel, ex.getMessage());
            return;
        } catch (IOException ex) {
            throw new IOException(ex);
        }

        // for existing users, hash is optional
        if (userExisted && securityJsonNode.get("hash").asString() == null) {
            // sanity check, this should usually not happen
            final String hash = ((Hashed) internalUsersConfiguration.getCEntry(username)).getHash();
            if (hash == null || hash.length() == 0) {
                internalErrorResponse(
                    channel,
                    "Existing user " + username + " has no password, and no new password or hash was specified."
                );
                return;
            }
            contentAsNode.put("hash", hash);
        }

        internalUsersConfiguration.remove(username);

        // checks complete, create or update the user
        Object userData = DefaultObjectMapper.readTree(contentAsNode, internalUsersConfiguration.getImplementingClass());
        internalUsersConfiguration.putCObject(username, userData);

        saveAndUpdateConfigs(
            this.securityIndexName,
            client,
            CType.INTERNALUSERS,
            internalUsersConfiguration,
            new OnSucessActionListener<IndexResponse>(channel) {

                @Override
                public void onResponse(IndexResponse response) {
                    if (userExisted) {
                        successResponse(channel, "'" + username + "' updated.");
                    } else {
                        createdResponse(channel, "'" + username + "' created.");
                    }

                }
            }
        );
    }

    /**
     * Overrides the GET request functionality to allow for the special case of requesting an auth token.
     *
     * @param channel The channel the request is coming through
     * @param request The request itself
     * @param client The client executing the request
     * @param content The content of the request parsed into a node
     * @throws IOException when parsing of configuration files fails (should not happen)
     */
    @Override
    protected void handlePost(final RestChannel channel, RestRequest request, Client client, final JsonNode content) throws IOException {

        final String username = request.param("name");

        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getConfigName(), true);
        filter(internalUsersConfiguration); // Hides hashes

        // no specific resource requested
        if (username == null || username.length() == 0) {

            notImplemented(channel, Method.POST);
            return;
        }

        final boolean userExisted = internalUsersConfiguration.exists(username);

        if (!userExisted) {
            notFound(channel, "Resource '" + username + "' not found.");
            return;
        }

        String authToken = "";
        try {
            if (request.uri().contains("/internalusers/" + username + "/authtoken") && request.uri().endsWith("/authtoken")) {  // Handle
                                                                                                                                // auth
                                                                                                                                // token
                                                                                                                                // fetching

                authToken = userService.generateAuthToken(username);
            } else { // Not an auth token request

                notImplemented(channel, Method.POST);
                return;
            }
        } catch (UserServiceException ex) {
            badRequestResponse(channel, ex.getMessage());
            return;
        } catch (IOException ex) {
            throw new IOException(ex);
        }

        if (!authToken.isEmpty()) {
            createdResponse(channel, "'" + username + "' authtoken generated " + authToken);
        } else {
            badRequestResponse(channel, "'" + username + "' authtoken failed to be created.");
        }
    }

    @Override
    protected void filter(SecurityDynamicConfiguration<?> builder) {
        super.filter(builder);
        // replace password hashes in addition. We must not remove them from the
        // Builder since this would remove users completely if they
        // do not have any addition properties like roles or attributes
        builder.clearHashes();
    }

    @Override
    protected ValidationResult postProcessApplyPatchResult(
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
            final ValidationResult validationResult = createValidator(resourceName).validate(request, passwordObject);
            ((ObjectNode) updatedResourceAsJsonNode).remove("password");
            ((ObjectNode) updatedResourceAsJsonNode).set("hash", new TextNode(hash(plainTextPassword.toCharArray())));
            return validationResult;
        }
        return null;
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
