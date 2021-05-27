/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.dlic.rest.api;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.dlic.rest.validation.InternalUsersValidator;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.Hashed;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.SecurityJsonNode;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import com.google.common.collect.ImmutableList;

import static org.opensearch.security.dlic.rest.support.Utils.hash;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class InternalUsersApiAction extends PatchableResourceApiAction {
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

    @Inject
    public InternalUsersApiAction(final Settings settings, final Path configPath, final RestController controller,
                                  final Client client, final AdminDNs adminDNs, final ConfigurationRepository cl,
                                  final ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator,
                                  ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool,
                auditLog);
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

        if (username == null || username.length() == 0) {
            badRequestResponse(channel, "No " + getResourceName() + " specified.");
            return;
        }

        // TODO it might be sensible to consolidate this with the overridden method in
        // order to minimize duplicated logic

        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getConfigName(), false);

        if (!isWriteable(channel, internalUsersConfiguration, username)) {
            return;
        }

        final ObjectNode contentAsNode = (ObjectNode) content;
        final SecurityJsonNode securityJsonNode = new SecurityJsonNode(contentAsNode);

        // Don't allow user to add non-existent role or a role for which role-mapping is hidden or reserved
        final List<String> securityRoles = securityJsonNode.get("opendistro_security_roles").asList();
        if (securityRoles != null) {
            for (final String role: securityRoles) {
                if (!isValidRolesMapping(channel, role)) return;
            }
        }

        // if password is set, it takes precedence over hash
        final String plainTextPassword = securityJsonNode.get("password").asString();
        final String origHash = securityJsonNode.get("hash").asString();
        if (plainTextPassword != null && plainTextPassword.length() > 0) {
            contentAsNode.remove("password");
            contentAsNode.put("hash", hash(plainTextPassword.toCharArray()));
        } else if (origHash != null && origHash.length() > 0) {
            contentAsNode.remove("password");
        } else if (plainTextPassword != null && plainTextPassword.isEmpty() && origHash == null) {
            contentAsNode.remove("password");
        }

        final boolean userExisted = internalUsersConfiguration.exists(username);

        // when updating an existing user password hash can be blank, which means no
        // changes

        // sanity checks, hash is mandatory for newly created users
        if (!userExisted && securityJsonNode.get("hash").asString() == null) {
            badRequestResponse(channel, "Please specify either 'hash' or 'password' when creating a new internal user.");
            return;
        }

        // for existing users, hash is optional
        if (userExisted && securityJsonNode.get("hash").asString() == null) {
            // sanity check, this should usually not happen
            final String hash = ((Hashed) internalUsersConfiguration.getCEntry(username)).getHash();
            if (hash == null || hash.length() == 0) {
                internalErrorResponse(channel,
                    "Existing user " + username + " has no password, and no new password or hash was specified.");
                return;
            }
            contentAsNode.put("hash", hash);
        }

        internalUsersConfiguration.remove(username);

        // checks complete, create or update the user
        internalUsersConfiguration.putCObject(username, DefaultObjectMapper.readTree(contentAsNode,  internalUsersConfiguration.getImplementingClass()));

        saveAnUpdateConfigs(client, request, CType.INTERNALUSERS, internalUsersConfiguration, new OnSucessActionListener<IndexResponse>(channel) {

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
                log.error(e);
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
