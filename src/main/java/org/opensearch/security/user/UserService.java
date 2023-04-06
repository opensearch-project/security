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
import java.net.UnknownServiceException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.Hashed;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecurityJsonNode;

import static org.opensearch.security.dlic.rest.support.Utils.hash;

/**
 * This class handles user registration and operations on behalf of the Security Plugin.
 */
public class UserService {

    protected final Logger log = LogManager.getLogger(this.getClass());
    ClusterService clusterService;
    static ConfigurationRepository configurationRepository;
    String securityIndex;
    Client client;
    final static String NO_PASSWORD_OR_HASH_MESSAGE = "Please specify either 'hash' or 'password' when creating a new internal user.";
    final static String RESTRICTED_CHARACTER_USE_MESSAGE = "A restricted character(s) was detected in the account name. Please remove: ";

    final static String SERVICE_ACCOUNT_PASSWORD_MESSAGE = "A password cannot be provided for a service account. Failed to register service account: ";

    final static String SERVICE_ACCOUNT_HASH_MESSAGE = "A password hash cannot be provided for service account. Failed to register service account: ";

    final static String NO_ACCOUNT_NAME_MESSAGE = "No account name was specified in the request.";
    private static CType getConfigName() {
        return CType.INTERNALUSERS;
    }

    static final List<String> RESTRICTED_FROM_USERNAME = ImmutableList.of(
            ":" // Not allowed in basic auth, see https://stackoverflow.com/a/33391003/533057
    );

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
    protected static final SecurityDynamicConfiguration<?> load(final CType config, boolean logComplianceEvent) {
        SecurityDynamicConfiguration<?> loaded = configurationRepository.getConfigurationsFromIndex(Collections.singleton(config), logComplianceEvent).get(config).deepClone();
        return DynamicConfigFactory.addStatics(loaded);
    }

    protected void saveAndUpdateConfiguration(final Client client, final CType cType,
                                              final SecurityDynamicConfiguration<?> configuration) {
        final IndexRequest ir = new IndexRequest(this.securityIndex);

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
     * @return
     * @throws UserServiceException
     * @throws IOException
     */
    public SecurityDynamicConfiguration<?> createOrUpdateAccount(String accountDetailsAsString) throws IOException {

        ObjectMapper mapper = new ObjectMapper();
        JsonNode accountDetails = mapper.readTree(accountDetailsAsString);
        final ObjectNode contentAsNode = (ObjectNode) accountDetails;
        final SecurityJsonNode securityJsonNode = new SecurityJsonNode(contentAsNode);
        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getConfigName(), false);

        String accountName = securityJsonNode.get("name").asString();

        if (accountName == null || accountName.length() == 0) { // Fail if field is present but empty
            throw new UserServiceException(NO_ACCOUNT_NAME_MESSAGE);
        }

        final Map<String, String> accountAttributes = new HashMap<>();

        if (!securityJsonNode.get("service").isNull() && securityJsonNode.get("service").asString() == "true") { // If this is a service account

            accountAttributes.put("service", "true"); // This attribute signifies that the account is a service account
            verifyServiceAccount(securityJsonNode, accountName);

        } else {

            // Not a service account
            final List<String> foundRestrictedContents = RESTRICTED_FROM_USERNAME.stream().filter(accountName::contains).collect(Collectors.toList());
            if (!foundRestrictedContents.isEmpty()) {
                final String restrictedContents = foundRestrictedContents.stream().map(s -> "'" + s + "'").collect(Collectors.joining(","));
                throw new UnknownServiceException(RESTRICTED_CHARACTER_USE_MESSAGE + restrictedContents);
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
                throw new UserServiceException(NO_PASSWORD_OR_HASH_MESSAGE);
            }

            // for existing users, hash is optional
            if (userExisted && securityJsonNode.get("hash").asString() == null) {
                // sanity check, this should usually not happen
                final String hash = ((Hashed) internalUsersConfiguration.getCEntry(accountName)).getHash();
                if (hash == null || hash.length() == 0) {
                    throw new UserServiceException("Existing user " + accountName + " has no password, and no new password or hash was specified.");
                }
                contentAsNode.put("hash", hash);
            }
        }

        internalUsersConfiguration.remove(accountName);
        contentAsNode.remove("name");

        internalUsersConfiguration.putCObject(accountName, DefaultObjectMapper.readTree(contentAsNode,  internalUsersConfiguration.getImplementingClass()));

        if (!securityJsonNode.get("service").isNull() && securityJsonNode.get("service").asString() == "true") { // Internal users update the config as part
            saveAndUpdateConfiguration(client, CType.INTERNALUSERS, internalUsersConfiguration);
        }
        return internalUsersConfiguration;
    }

    private void verifyServiceAccount(SecurityJsonNode securityJsonNode, String accountName) {

        final String plainTextPassword = securityJsonNode.get("password").asString();
        final String origHash = securityJsonNode.get("hash").asString();

        if (plainTextPassword != null && plainTextPassword.length() > 0) {
            throw new UserServiceException(SERVICE_ACCOUNT_PASSWORD_MESSAGE + accountName);
        }

        if (origHash != null && origHash.length() > 0) {
            throw new UserServiceException(SERVICE_ACCOUNT_HASH_MESSAGE + accountName);
        }
    }
}
