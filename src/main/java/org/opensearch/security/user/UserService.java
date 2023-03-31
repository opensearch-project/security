/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.user;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableList;

import org.opensearch.ExceptionsHelper;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.securityconf.Hashed;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.InternalUserV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecurityJsonNode;

import static org.opensearch.security.dlic.rest.support.Utils.hash;

/**
 * This class handles user registration and operations on behalf of the Security Plugin.
 */
public class UserService {

    ClusterService clusterService;
    static ConfigurationRepository configurationRepository;
    String securityIndex;
    Client client;

    final String NO_PASSWORD_OR_HASH_MESSAGE = "Please specify either 'hash' or 'password' when creating a new internal user.";
    final String RESTRICTED_CHARACTER_USE_MESSAGE = "A restricted character(s) was detected in the account name. Please remove: ";

    final String SERVICE_ACCOUNT_PASSWORD_MESSAGE = "A password cannot be provided for a service account. Failed to register service account: ";

    final String SERVICE_ACCOUNT_HASH_MESSAGE = "A password hash cannot be provided for service account. Failed to register service account: ";

    final String NO_ACCOUNT_NAME_MESSAGE = "No account name was specified in the request.";
    protected static CType getConfigName() {
        return CType.INTERNALUSERS;
    }

    static final List<String> RESTRICTED_FROM_USERNAME = ImmutableList.of(
            ":" // Not allowed in basic auth, see https://stackoverflow.com/a/33391003/533057
    );

    // CreateUser
    // Update User
    // List User
    // Get User
    // This should be for all internal users instead of just service accounts
    // Make a SecurityPluginUser object
    // Work backwards from remaking this as a User Service -- can mostly reuse from current state
    // Want to check that when code is created or updated, you check if it is a service account and turn on properties
    // For example: Creator/owner of service account (extension or user)
    // All end-to-end tests can be written without extensions and we can test everything
    // Should not need to test create, update, list, get as unit tests but will want to test service account creation and deletion
    // I.e. service account is invalid because no owner -- can leave tests till later.


    @Inject
    public UserService(
            ClusterService clusterService,
            ConfigurationRepository configurationRepository,
            Settings settings,
            Client client
    ) {
        this.clusterService = clusterService;
        this.configurationRepository = configurationRepository;
        this.securityIndex = settings.get(ConfigConstants.SECURITY_CONFIG_INDEX_NAME,
                ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        this.client = client;
    }

    /**
     * Load data for a given CType
     * @param config CType whose data is to be loaded in-memory
     * @return configuration loaded with given CType data
     */
    protected static final SecurityDynamicConfiguration<?> load(final CType config) {
        SecurityDynamicConfiguration<?> loaded = configurationRepository.getConfigurationsFromIndex(Collections.singleton(config))
                .get(config)
                .deepClone();
        return loaded;
    }

    protected void saveAndUpdateConfiguration(final Client client, final CType cType,
                                              final SecurityDynamicConfiguration<?> configuration) {
        final IndexRequest ir = new IndexRequest(this.securityIndex);

        // final String type = "_doc";
        final String id = cType.toLCString();

        configuration.removeStatic();

        try {
            client.index(ir.id(id)
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                            .setIfSeqNo(configuration.getSeqNo())
                            .setIfPrimaryTerm(configuration.getPrimaryTerm())
                            .source(id, XContentHelper.toXContent(configuration, XContentType.JSON, false)));
        } catch (IOException e) {
            throw ExceptionsHelper.convertToOpenSearchException(e);
        }
    }

    /**
     * This function will handle the creation or update of a user account.
     *
     * @param accountDetailsAsString A string JSON of different account configurations.
     * @throws ServiceAccountRegistrationException
     * @throws IOException
     */
    public void createOrUpdateAccount(String accountDetailsAsString) throws IOException, AccountCreateOrUpdateException, ServiceAccountRegistrationException {

        ObjectMapper mapper = new ObjectMapper();
        JsonNode accountDetails = mapper.readTree(accountDetailsAsString);
        final ObjectNode contentAsNode = (ObjectNode) accountDetails;
        final SecurityJsonNode securityJsonNode = new SecurityJsonNode(contentAsNode);
        final List<String> securityRoles = securityJsonNode.get("opendistro_security_roles").asList();
        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getConfigName());

        String accountName = securityJsonNode.get("name").asString();

        if (accountName == null || accountName.length() == 0) { // Fail if field is present but empty
            throw new AccountCreateOrUpdateException(NO_ACCOUNT_NAME_MESSAGE);
        }

        final Map<String, String> accountAttributes = new HashMap<>();

        if (!securityJsonNode.get("service").isNull() && securityJsonNode.get("service").asString() == "true") { // If this is a service account

            // final DiscoveryExtensionNode extensionInformation = OpenSearchSecurityPlugin.GuiceHolder.getExtensionsManager().getExtensionIdMap().get(extensionUniqueId);
            // extensionInformation.getSecurityConfiguration(); TODO: Need to make it so that we can get the extension configuration information
            // extensionInformation.parseToJson();
            // Add default role option for extensions which do not specify their own role
            accountAttributes.put("service", "true"); // This attribute signifies that the account is a service account

            // A password cannot be provided for a Service account.
            final String plainTextPassword = securityJsonNode.get("password").asString();
            final String origHash = securityJsonNode.get("hash").asString();

            if (plainTextPassword != null && plainTextPassword.length() > 0) {
                throw new ServiceAccountRegistrationException(SERVICE_ACCOUNT_PASSWORD_MESSAGE + accountName);
            }

            if (origHash != null && origHash.length() > 0) {
                throw new ServiceAccountRegistrationException(SERVICE_ACCOUNT_HASH_MESSAGE + accountName);
            }
        } else { // Not a service account

            final List<String> foundRestrictedContents = RESTRICTED_FROM_USERNAME.stream().filter(accountName::contains).collect(Collectors.toList());
            if (!foundRestrictedContents.isEmpty()) {
                final String restrictedContents = foundRestrictedContents.stream().map(s -> "'" + s + "'").collect(Collectors.joining(","));
                throw new AccountCreateOrUpdateException(RESTRICTED_CHARACTER_USE_MESSAGE + restrictedContents);
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

            final boolean userExisted = internalUsersConfiguration.exists(accountName);

            // when updating an existing user password hash can be blank, which means no
            // changes

            // sanity checks, hash is mandatory for newly created users
            if (!userExisted && securityJsonNode.get("hash").asString() == null) {
                throw new AccountCreateOrUpdateException(NO_PASSWORD_OR_HASH_MESSAGE);
            }

            // for existing users, hash is optional
            if (userExisted && securityJsonNode.get("hash").asString() == null) {
                // sanity check, this should usually not happen
                final String hash = ((Hashed) internalUsersConfiguration.getCEntry(accountName)).getHash();
                if (hash == null || hash.length() == 0) {
                    throw new AccountCreateOrUpdateException("Existing user " + accountName + " has no password, and no new password or hash was specified.");
                }
                contentAsNode.put("hash", hash);
            }
        }


        internalUsersConfiguration.remove(accountName);

        internalUsersConfiguration.putCObject(accountName, DefaultObjectMapper.readTree(contentAsNode,  internalUsersConfiguration.getImplementingClass()));

        if (!securityJsonNode.get("service").isNull() && securityJsonNode.get("service").asString() == "true") { // Internal users update the config as part
            saveAndUpdateConfiguration(client, CType.INTERNALUSERS, internalUsersConfiguration);
        }
    }

    public static List<String> listServiceAccounts() {

        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getConfigName());

        List<String> serviceAccounts = new ArrayList<>();
        for (Map.Entry<String, ?> entry : internalUsersConfiguration.getCEntries().entrySet()) {

            final InternalUserV7 internalUserEntry = (InternalUserV7) entry.getValue();
            final Map accountAttributes = internalUserEntry.getAttributes();
            final String accountName = entry.getKey();
            if (accountAttributes.containsKey("service") && accountAttributes.get("service") == "true") {
                serviceAccounts.add(accountName);
            }
        }
        return serviceAccounts;
    }

    public static List<String> listInternalUsers() {

        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getConfigName());

        List<String> internalUserAccounts = new ArrayList<>();
        for (Map.Entry<String, ?> entry : internalUsersConfiguration.getCEntries().entrySet()) {

            final InternalUserV7 internalUserEntry = (InternalUserV7) entry.getValue();
            final Map accountAttributes = internalUserEntry.getAttributes();
            final String accountName = entry.getKey();
            if (!accountAttributes.containsKey("service") || accountAttributes.get("service") == "false") {
                internalUserAccounts.add(accountName);
            }
        }
        return internalUserAccounts;
    }

    public static Set<String> listUserAccounts() {

        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getConfigName());
        return internalUsersConfiguration.getCEntries().keySet();
    }

    public static boolean accountExists(String accountName) {

        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getConfigName());
        return internalUsersConfiguration.exists(accountName);
    }
}
