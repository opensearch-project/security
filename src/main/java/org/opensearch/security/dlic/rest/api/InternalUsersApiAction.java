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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.google.common.collect.ImmutableList;

import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.dlic.rest.validation.InternalUsersValidator;
import org.opensearch.security.privileges.PrivilegesEvaluator;
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

    private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
            new Route(Method.GET, "/user/{name}"),
            new Route(Method.GET, "/user/"),
            new Route(Method.DELETE, "/user/{name}"),
            new Route(Method.PUT, "/user/{name}"),

            // corrected mapping, introduced in OpenSearch Security
            new Route(Method.GET, "/internalusers/{name}"),
            new Route(Method.GET, "/internalusers/"),
            new Route(Method.DELETE, "/internalusers/{name}"),
            new Route(Method.PUT, "/internalusers/{name}"),
            new Route(Method.PATCH, "/internalusers/"),
            new Route(Method.PATCH, "/internalusers/{name}")
    ));

    UserService userService;

    @Inject
    public InternalUsersApiAction(final Settings settings, final Path configPath, final RestController controller,
                                  final Client client, final AdminDNs adminDNs, final ConfigurationRepository cl,
                                  final ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator,
                                  ThreadPool threadPool, UserService userService, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool,
                auditLog);
        this.userService = userService;
    }

    @Override
    protected boolean hasPermissionsToCreate(final SecurityDynamicConfiguration<?> dynamicConfigFactory,
                                             final Object content,
                                             final String resourceName) {
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
    protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {

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
            for (final String role: securityRoles) {
                if (!isValidRolesMapping(channel, role)) {
                    return;
                }
            }
        }

        final boolean userExisted = internalUsersConfiguration.exists(username);

        // when updating an existing user password hash can be blank, which means no
        // changes

        try {
            if (request.hasParam("owner")) {
                ((ObjectNode) content).put("owner", request.param("owner"));
            }
            if (request.hasParam("isEnabled")) {
                ((ObjectNode) content).put("isEnabled", request.param("isEnabled"));
            }
            ((ObjectNode) content).put("name", username);
            internalUsersConfiguration = userService.createOrUpdateAccount((ObjectNode) content);
        }
        catch (UserServiceException ex) {
            badRequestResponse(channel, ex.getMessage());
            return;
        }
        catch (IOException ex) {
            throw new IOException(ex);
        }


        saveAndUpdateConfigs(this.securityIndexName,client, CType.INTERNALUSERS, internalUsersConfiguration, new OnSucessActionListener<IndexResponse>(channel) {

            @Override
            public void onResponse(IndexResponse response) {
                if (userExisted) {
                    successResponse(channel, "'" + username + "' updated.");
                } else {
                    createdResponse(channel, "'" + username + "' created.");
                }

            }
        });
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
    protected AbstractConfigurationValidator postProcessApplyPatchResult(RestChannel channel, RestRequest request, JsonNode existingResourceAsJsonNode,
                                                                         JsonNode updatedResourceAsJsonNode, String resourceName) {
        AbstractConfigurationValidator retVal = null;
        JsonNode passwordNode = updatedResourceAsJsonNode.get("password");

        if (passwordNode != null) {
            String plainTextPassword = passwordNode.asText();
            try {
                XContentBuilder builder = channel.newBuilder();
                builder.startObject();
                builder.field("password", plainTextPassword);
                builder.endObject();
                retVal = getValidator(request, BytesReference.bytes(builder), resourceName);
            } catch (IOException e) {
                log.error(e.toString());
            }

            ((ObjectNode) updatedResourceAsJsonNode).remove("password");
            ((ObjectNode) updatedResourceAsJsonNode).set("hash", new TextNode(hash(plainTextPassword.toCharArray())));
            return retVal;
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
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params) {
        return new InternalUsersValidator(request, isSuperAdmin(), ref, this.settings, params);
    }
}
