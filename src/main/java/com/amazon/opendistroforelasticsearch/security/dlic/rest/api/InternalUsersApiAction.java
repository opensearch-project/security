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

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.InternalUsersValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.Hashed;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.SecurityJsonNode;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import com.google.common.collect.ImmutableList;

import static com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils.hash;

public class InternalUsersApiAction extends PatchableResourceApiAction {
    private static final List<Route> routes = ImmutableList.of(
            new Route(Method.GET, "/_opendistro/_security/api/user/{name}"),
            new Route(Method.GET, "/_opendistro/_security/api/user/"),
            new Route(Method.DELETE, "/_opendistro/_security/api/user/{name}"),
            new Route(Method.PUT, "/_opendistro/_security/api/user/{name}"),

            // corrected mapping, introduced in Open Distro Security
            new Route(Method.GET, "/_opendistro/_security/api/internalusers/{name}"),
            new Route(Method.GET, "/_opendistro/_security/api/internalusers/"),
            new Route(Method.DELETE, "/_opendistro/_security/api/internalusers/{name}"),
            new Route(Method.PUT, "/_opendistro/_security/api/internalusers/{name}"),
            new Route(Method.PATCH, "/_opendistro/_security/api/internalusers/"),
            new Route(Method.PATCH, "/_opendistro/_security/api/internalusers/{name}")
    );

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

        if (isHidden(internalUsersConfiguration, username)) {
            forbidden(channel, "Resource '" + username + "' is not available.");
            return;
        }

        // check if resource is writeable
        if (!isReservedAndAccessible(internalUsersConfiguration, username)) {
            forbidden(channel, "Resource '" + username + "' is read-only.");
            return;
        }

        final ObjectNode contentAsNode = (ObjectNode) content;
        final SecurityJsonNode securityJsonNode = new SecurityJsonNode(contentAsNode);

        // Don't allow user to add hidden, reserved or non-existent role
        final List<String> opendistroSecurityRoles = securityJsonNode.get("opendistro_security_roles").asList();
        if (opendistroSecurityRoles != null) {
            final SecurityDynamicConfiguration<?> rolesConfiguration = load(CType.ROLES, false);
            for (final String role: opendistroSecurityRoles) {

                if (!rolesConfiguration.exists(role) || isHidden(rolesConfiguration, role)) {
                    notFound(channel, "Role '"+role+"' is not found.");
                    return;
                }

                if (isReserved(rolesConfiguration, role)) {
                    forbidden(channel, "Role '" + role + "' is reserved.");
                    return;
                }
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
