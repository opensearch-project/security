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

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.configuration.IndexBaseConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AccountValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

import static com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils.hash;

/**
 * Rest API action to fetch or update account details of the signed-in user.
 * Currently this action serves GET and PUT request for /_opendistro/_security/api/account endpoint
 */
public class AccountApiAction extends AbstractApiAction {

    private static final String RESOURCE_NAME = "account";
    private final PrivilegesEvaluator privilegesEvaluator;
    private final ThreadContext threadContext;
    private final IndexBaseConfigurationRepository indexBaseConfigurationRepository;

    public AccountApiAction(final Settings settings, final Path configPath, final RestController controller,
                            final Client client, final AdminDNs adminDNs, final IndexBaseConfigurationRepository indexBaseConfigurationRepository,
                            final ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator privilegesEvaluator,
                            ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, indexBaseConfigurationRepository, cs, principalExtractor, privilegesEvaluator, threadPool,
                auditLog);
        this.indexBaseConfigurationRepository = indexBaseConfigurationRepository;
        this.privilegesEvaluator = privilegesEvaluator;
        this.threadContext = threadPool.getThreadContext();
    }

    @Override
    protected void registerHandlers(RestController controller, Settings settings) {
        controller.registerHandler(RestRequest.Method.GET, "/_opendistro/_security/api/account", this);
        controller.registerHandler(RestRequest.Method.PUT, "/_opendistro/_security/api/account", this);
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
     * @param channel channel to return response
     * @param request request to be served
     * @param client client
     * @param additionalSettings settings
     * @throws IOException
     */
    @Override
    protected void handleGet(final RestChannel channel, RestRequest request, Client client, Settings.Builder additionalSettings) throws IOException {
        final XContentBuilder builder = channel.newBuilder();
        BytesRestResponse response;

        try {
            builder.startObject();
            final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            if (user != null) {
                final TransportAddress remoteAddress = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
                final Set<String> securityRoles = privilegesEvaluator.mapRoles(user, remoteAddress);

                final Tuple<Long, Settings> configurationSettings = loadAsSettings(getConfigName(), false);
                Boolean readOnly = configurationSettings.v2().getAsBoolean(user.getName() + "." + ConfigConstants.CONFIGKEY_READONLY,
                        Boolean.FALSE);
                final Tuple<Long, Settings.Builder> internalUser = load(getConfigName(), false);
                final Map<String, Object> config = Utils.convertJsonToxToStructuredMap(internalUser.v2().build());

                builder.field("user_name", user.getName())
                        .field("is_reserved", readOnly)
                        .field("is_hidden", isHidden(configurationSettings.v2(), user.getName()))
                        .field("is_internal_user", config.containsKey(user.getName()))
                        .field("user_requested_tenant", user.getRequestedTenant())
                        .field("backend_roles", user.getRoles())
                        .field("custom_attribute_names", user.getCustomAttributesMap().keySet())
                        .field("tenants", privilegesEvaluator.mapTenants(user, securityRoles))
                        .field("roles", securityRoles);
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
     * @param channel channel to return response
     * @param request request to be served
     * @param client client
     * @param additionalSettingsBuilder settings
     * @throws IOException
     */
    @Override
    protected void handlePut(RestChannel channel, final RestRequest request, final Client client,
                             final Settings.Builder additionalSettingsBuilder) throws IOException {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        String username = user.getName();

        final Tuple<Long, Settings> existingAsSettings = loadAsSettings(getConfigName(), false);
        final Tuple<Long, Settings.Builder> internaluser = load(ConfigConstants.CONFIGNAME_INTERNAL_USERS, false);
        final Map<String, Object> config = Utils.convertJsonToxToStructuredMap(internaluser.v2().build());


        if (!config.containsKey(username)) {
            notFound(channel, "Could not find user.");
            return;
        }

        if (isHidden(existingAsSettings.v2(), username)) {
            forbidden(channel, "Resource '" + username + "' is not available.");
            return;
        }

        if (isReadOnly(existingAsSettings.v2(), username)) {
            forbidden(channel, "Resource '"+ username +"' is read-only.");
            return;
        }

        final Settings settings = indexBaseConfigurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_INTERNAL_USERS);
        final String currentPassword = additionalSettingsBuilder.get("current_password");
        final String hash = settings.get(username + ".hash");
        if (hash == null || !OpenBSDBCrypt.checkPassword(hash, currentPassword.toCharArray())) {
            badRequestResponse(channel, "Could not validate your current password.");
            return;
        }

        additionalSettingsBuilder.remove("current_password");

        // if password is set, it takes precedence over hash
        final String plainTextPassword = additionalSettingsBuilder.get("password");
        final String origHash = additionalSettingsBuilder.get("hash");
        if (plainTextPassword != null && plainTextPassword.length() > 0) {
            additionalSettingsBuilder.remove("password");
            additionalSettingsBuilder.put("hash", hash(plainTextPassword.toCharArray()));
        } else if (origHash != null && origHash.length() > 0) {
            additionalSettingsBuilder.remove("password");
        } else if (plainTextPassword != null && plainTextPassword.isEmpty() && origHash == null) {
            additionalSettingsBuilder.remove("password");
        }

        config.remove(username);

        // checks complete, create or update the user
        config.put(username, Utils.convertJsonToxToStructuredMap(additionalSettingsBuilder.build()));

        saveAnUpdateConfigs(client, request, ConfigConstants.CONFIGNAME_INTERNAL_USERS, Utils.convertStructuredMapToBytes(config), new OnSucessActionListener<IndexResponse>(channel) {
            @Override
            public void onResponse(IndexResponse response) {
                successResponse(channel, "'" + username + "' updated.");
            }
        }, internaluser.v1());
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params) {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
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
    protected void filter(Settings.Builder builder) {
        super.filter(builder);
        // replace password hashes in addition. We must not remove them from the
        // Builder since this would remove users completely if they
        // do not have any addition properties like roles or attributes
        Set<String> entries = builder.build().names();
        for (String key : entries) {
            builder.put(key + ".hash", "");
        }
    }

    @Override
    protected String getConfigName() {
        return ConfigConstants.CONFIGNAME_INTERNAL_USERS;
    }
}
