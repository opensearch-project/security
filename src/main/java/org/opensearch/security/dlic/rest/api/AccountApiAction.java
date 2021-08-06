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

import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.dlic.rest.validation.AccountValidator;
import org.opensearch.security.dlic.rest.validation.SavedTenantValidator;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.Hashed;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.InternalUserV7;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.security.user.User;
import com.fasterxml.jackson.databind.JsonNode;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.Strings;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.rest.RestStatus;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import com.google.common.collect.ImmutableList;

import static org.opensearch.security.dlic.rest.support.Utils.hash;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * Rest API action to fetch or update account details of the signed-in user.
 * Currently this action serves GET and PUT request for /_opendistro/_security/api/account endpoint
 */
public class AccountApiAction extends AbstractApiAction {
    private static final String SAVED_TENANT = "saved_tenant";
    private static final String RESOURCE_NAME = "account";
    private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
            new Route(Method.GET, "/account"),
            new Route(Method.PUT, "/account"),
            new Route(Method.GET, "/account/" + SAVED_TENANT),
            new Route(Method.PUT, "/account/" + SAVED_TENANT)
    ));

    // each user has access to the global tenant
    private final String DEFAULT_TENANT = "global-tenant";
    // PRIVATE_TENANT represents a user's personal tenant
    // each user should have access to their own tenant
    // if user A sets user B's 'saved_tenant' = PRIVATE_TENANT,
    //     user B will see their own private tenant when they
    //     log in (as opposed to user A's private tenant)
    private final String PRIVATE_TENANT = "private-tenant";

    private final PrivilegesEvaluator privilegesEvaluator;
    private final ThreadContext threadContext;

    public AccountApiAction(Settings settings,
                            Path configPath,
                            RestController controller,
                            Client client,
                            AdminDNs adminDNs,
                            ConfigurationRepository cl,
                            ClusterService cs,
                            PrincipalExtractor principalExtractor,
                            PrivilegesEvaluator privilegesEvaluator,
                            ThreadPool threadPool,
                            AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, privilegesEvaluator, threadPool, auditLog);
        this.privilegesEvaluator = privilegesEvaluator;
        this.threadContext = threadPool.getThreadContext();
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    /**
     * GET request to fetch account details
     *
     * Sample request:
     * GET _opendistro/_security/api/account
     *
     * Sample response:
     * {
     *   "user_name" : "test",
     *   "is_reserved" : false,
     *   "is_hidden" : false,
     *   "is_internal_user" : true,
     *   "user_requested_tenant" : "__user__",
     *   "backend_roles" : [ ],
     *   "custom_attribute_names" : [ ],
     *   "tenants" : {
     *     "test" : true
     *   },
     *   "roles" : [
     *     "own_index"
     *   ]
     * }
     * 
     * GET request to fetch user's saved tenant
     * 
     * Sample request:
     * GET _opendistro/security/api/account/saved_tenant
     * 
     * Sample response:
     * {
     *      "status":"OK",
     *      "body":{
     *          "saved_tenant":"global-tenant"
     *      }
     * }
     *
     * @param channel channel to return response
     * @param request request to be served
     * @param client client
     * @param content content body
     * @throws IOException
     */
    @Override
    protected void handleGet(RestChannel channel, RestRequest request, Client client, final JsonNode content) throws IOException {
        final XContentBuilder builder = channel.newBuilder();
        BytesRestResponse response;

        try {
            builder.startObject();
            final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            final String username = user.getName();
            final SecurityDynamicConfiguration<?> internalUser = load(CType.INTERNALUSERS, false);
            if (user != null) {
                final TransportAddress remoteAddress = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
                final Set<String> securityRoles = privilegesEvaluator.mapRoles(user, remoteAddress);
                final SecurityDynamicConfiguration<?> configuration = load(getConfigName(), false);
            
                
                if (request.path().endsWith(SAVED_TENANT)){
                   if (configuration.exists(user.getName())){
                        // not responsible for verifying tenant accessibility
                        // check for tenant accessibility is done when user tries to access said tenant
                        InternalUserV7 iu = (InternalUserV7) internalUser.getCEntry(username);
                        builder.field("saved_tenant", iu.getSaved_tenant());
                    } else {
                        builder.field("message", "Sorry, saved tenant is currently only stored for existing internal users.");
                    }
                } else {
                    builder.field("user_name", user.getName())
                        .field("is_reserved", isReserved(configuration, user.getName()))
                        .field("is_hidden", configuration.isHidden(user.getName()))
                        .field("is_internal_user", configuration.exists(user.getName()))
                        .field("user_requested_tenant", user.getRequestedTenant())
                        .field("backend_roles", user.getRoles())
                        .field("custom_attribute_names", user.getCustomAttributesMap().keySet())
                        .field("tenants", privilegesEvaluator.mapTenants(user, securityRoles))
                        .field("roles", securityRoles);
                }
            }
            builder.endObject();

            response = new BytesRestResponse(RestStatus.OK, builder);
        } catch (final Exception exception) {
            log.error(exception.toString(), exception);

            builder.startObject()
                    .field("error", exception.toString())
                    .endObject();

            response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
        }
        channel.sendResponse(response);
    }

    /**
     * PUT request to update account password.
     *
     * Sample request:
     * PUT _opendistro/_security/api/account
     * {
     *     "current_password": "old-pass",
     *     "password": "new-pass"
     * }
     *
     * Sample response:
     * {
     *     "status":"OK",
     *     "message":"'test' updated."
     * }
     * 
     * PUT request to update account saved tenant
     * 
     * Sample request:
     * PUT _opendistro/security/api/account/saved_tenant
     * {
     *      "saved_tenant":"arbitrary-tenant"
     * }
     * 
     * Sample response:
     * {
     *      "status":"OK",
     *      "message":"'saved_tenant' updated"
     * }
     * 
     * @param channel channel to return response
     * @param request request to be served
     * @param client client
     * @param content content body
     * @throws IOException
     */
    @Override
    protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        final String username = user.getName();
        final SecurityDynamicConfiguration<?> internalUser = load(CType.INTERNALUSERS, false);

        if (!internalUser.exists(username)) {
            notFound(channel, "Could not find user.");
            return;
        }

        if (!isWriteable(channel, internalUser, username)) {
            return;
        }

        final SecurityJsonNode securityJsonNode = new SecurityJsonNode(content);
        final Hashed internalUserEntry = (Hashed) internalUser.getCEntry(username);
        final SecurityDynamicConfiguration<?> configuration = load(getConfigName(), false);
        if (request.path().endsWith(SAVED_TENANT)){
            if (configuration.exists(user.getName())){
                SecurityDynamicConfiguration<?> rolesMappings = load(CType.ROLESMAPPING, false);
                InternalUserV7 iu = (InternalUserV7) internalUser.getCEntry(username);
                final String newSavedTenant = content.get("saved_tenant").asText();
                if (!(newSavedTenant.equals(DEFAULT_TENANT) || newSavedTenant.equals(PRIVATE_TENANT))){
                    /*
                    TODO: implement tenant validity checks
                    boolean tenantExists = true; // assert passed saved tenant exists
                    boolean userHasAccessToTenant = true; // assert user has access to passed saved tenant
                    if (tenantExists && userHasAccessToTenant){
                        iu.setSaved_tenant(content.get("saved_tenant").asText());
                    } else { // case: trying to set user's tenant to a nonexistent or unaccessible (by user) tenant
                        badRequestResponse(channel, "User does not have access to provided tenant.");
                    return;
                    }
                    */
                }
                iu.setSaved_tenant(newSavedTenant);
            } 
            else {
                badRequestResponse(channel, "Sorry, saved tenant is currently only stored for existing internal users.");
                return;
            }
        } else{
            final String currentPassword = content.get("current_password").asText();
            final String currentHash = internalUserEntry.getHash();
    
            if (currentHash == null || !OpenBSDBCrypt.checkPassword(currentHash, currentPassword.toCharArray())) {
                badRequestResponse(channel, "Could not validate your current password.");
                return;
            }
    
            // if password is set, it takes precedence over hash
            final String password = securityJsonNode.get("password").asString();
            final String hash;
            if (Strings.isNullOrEmpty(password)) {
                hash = securityJsonNode.get("hash").asString();
            } else {
                hash = hash(password.toCharArray());
            }
            if (Strings.isNullOrEmpty(hash)) {
                badRequestResponse(channel, "Both provided password and hash cannot be null/empty.");
                return;
            }
            internalUserEntry.setHash(hash);
        }
        saveAnUpdateConfigs(client, request, CType.INTERNALUSERS, internalUser, new OnSucessActionListener<IndexResponse>(channel) {
            @Override
            public void onResponse(IndexResponse response) {
                successResponse(channel, "'" + username + "' updated.");
            }
        });
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params) {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        if (request.path().endsWith(SAVED_TENANT)){
            return new SavedTenantValidator(request, ref, this.settings, user.getName());
        }
        return new AccountValidator(request, ref, this.settings, user.getName());
    }

    @Override
    protected String getResourceName() {
        return RESOURCE_NAME;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.ACCOUNT;
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
    protected CType getConfigName() {
        return CType.INTERNALUSERS;
    }
}
