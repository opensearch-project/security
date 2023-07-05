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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.opensearch.security.dlic.rest.support.Utils.universalHash;

/**
 * This class handles user registration and operations on behalf of the Security Plugin.
 */
public class UserService {

    protected final Logger log = LogManager.getLogger(this.getClass());
    ClusterService clusterService;
    ConfigurationRepository configurationRepository;
    String securityIndex;
    Client client;

    final static String NO_PASSWORD_OR_HASH_MESSAGE = "Please specify either 'hash' or 'password' when creating a new internal user.";
    final static String RESTRICTED_CHARACTER_USE_MESSAGE = "A restricted character(s) was detected in the account name. Please remove: ";

    final static String SERVICE_ACCOUNT_PASSWORD_MESSAGE = "A password cannot be provided for a service account. Failed to register service account: ";

    final static String SERVICE_ACCOUNT_HASH_MESSAGE = "A password hash cannot be provided for service account. Failed to register service account: ";

    final static String NO_ACCOUNT_NAME_MESSAGE = "No account name was specified in the request.";

    final static String FAILED_ACCOUNT_RETRIEVAL_MESSAGE = "The account specified could not be accessed at this time.";
    final static String AUTH_TOKEN_GENERATION_MESSAGE = "An auth token could not be generated for the specified account.";

    final static String FAILED_CLEAR_HASH_MESSAGE = "The hash could not be cleared from the specified account.";

    private static CType getUserConfigName() {
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
    protected final SecurityDynamicConfiguration<?> load(final CType config, boolean logComplianceEvent) {
        SecurityDynamicConfiguration<?> loaded = configurationRepository.getConfigurationsFromIndex(Collections.singleton(config), logComplianceEvent).get(config).deepClone();
        return DynamicConfigFactory.addStatics(loaded);
    }

    /**
     * This function will handle the creation or update of a user account.
     *
     * @param contentAsNode An object node of different account configurations.
     * @return InternalUserConfiguration with the new/updated user
     */
    public SecurityDynamicConfiguration<?> createOrUpdateAccount(ObjectNode contentAsNode) throws IOException, NoSuchAlgorithmException {

        SecurityJsonNode securityJsonNode = new SecurityJsonNode(contentAsNode);

        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getUserConfigName(), false);
        String accountName = securityJsonNode.get("name").asString();

        if (accountName == null || accountName.length() == 0) { // Fail if field is present but empty
            throw new UserServiceException(NO_ACCOUNT_NAME_MESSAGE);
        }

        SecurityJsonNode attributeNode = securityJsonNode.get("attributes");

        if (!attributeNode.get("service").isNull() && Objects.requireNonNull(attributeNode.get("service").asString()).equalsIgnoreCase("true"))
        { // If this is a service account
            verifyServiceAccount(securityJsonNode, accountName);
            String password = generatePassword();
            contentAsNode.put("hash", universalHash(password));
            contentAsNode.put("service", "true");
        } else{
            contentAsNode.put("service", "false");
        }

        securityJsonNode = new SecurityJsonNode(contentAsNode);
        final List<String> foundRestrictedContents = RESTRICTED_FROM_USERNAME.stream().filter(accountName::contains).collect(Collectors.toList());
        if (!foundRestrictedContents.isEmpty()) {
            final String restrictedContents = foundRestrictedContents.stream().map(s -> "'" + s + "'").collect(Collectors.joining(","));
            throw new UserServiceException(RESTRICTED_CHARACTER_USE_MESSAGE + restrictedContents);
        }

        // if password is set, it takes precedence over hash
        final String plainTextPassword = securityJsonNode.get("password").asString();
        final String origHash = securityJsonNode.get("hash").asString();
        if (plainTextPassword != null && plainTextPassword.length() > 0) {
            contentAsNode.remove("password");
            contentAsNode.put("hash", universalHash(plainTextPassword));
        } else if (origHash != null && origHash.length() > 0) {
            contentAsNode.remove("password");
        } else if (plainTextPassword != null && origHash == null) {
            contentAsNode.remove("password");
        }

        if (!attributeNode.get("enabled").isNull()) {
            contentAsNode.put("enabled", securityJsonNode.get("enabled").asString());
        }

        final boolean userExisted = internalUsersConfiguration.exists(accountName);

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

        internalUsersConfiguration.remove(accountName);
        contentAsNode.remove("name");

        internalUsersConfiguration.putCObject(accountName, DefaultObjectMapper.readTree(contentAsNode,  internalUsersConfiguration.getImplementingClass()));
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

    /**
     * This will be swapped in for a real solution once one is decided on.
     *
     * @return A password for a service account.
     */
    private String generatePassword() {
        return "superSecurePassword";
    }

    /**
     * This function retrieves the auth token associated with a service account.
     * Fails if the provided account is not a service account or account is not enabled.
     *
     * @param accountName A string representing the name of the account
     * @return A string auth token
     */
    public String generateAuthToken(String accountName) throws IOException {

        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getUserConfigName(), false);

        if (!internalUsersConfiguration.exists(accountName)) {
            throw new UserServiceException(FAILED_ACCOUNT_RETRIEVAL_MESSAGE);
        }

        String authToken;
        try {
            JsonNode accountDetails = DefaultObjectMapper.readTree(internalUsersConfiguration.getCEntry(accountName).toString());
            final ObjectNode contentAsNode = (ObjectNode) accountDetails;
            SecurityJsonNode securityJsonNode = new SecurityJsonNode(contentAsNode);

            Optional.of(securityJsonNode.get("service"))
                    .map(SecurityJsonNode::asString)
                    .filter("true"::equalsIgnoreCase)
                    .orElseThrow(() -> new UserServiceException(AUTH_TOKEN_GENERATION_MESSAGE));


            Optional.of(securityJsonNode.get("enabled"))
                    .map(SecurityJsonNode::asString)
                    .filter("true"::equalsIgnoreCase)
                    .orElseThrow(() -> new UserServiceException(AUTH_TOKEN_GENERATION_MESSAGE));

            // Generate a new password for the account and store the hash of it
            String plainTextPassword = generatePassword();
            contentAsNode.put("hash", universalHash(plainTextPassword));
            contentAsNode.put("enabled", "true");
            contentAsNode.put("service", "true");

            // Update the internal user associated with the auth token
            internalUsersConfiguration.remove(accountName);
            contentAsNode.remove("name");
            internalUsersConfiguration.putCObject(accountName, DefaultObjectMapper.readTree(contentAsNode,  internalUsersConfiguration.getImplementingClass()));
            saveAndUpdateConfigs(getUserConfigName().toString(), client, CType.INTERNALUSERS, internalUsersConfiguration);


            authToken = Base64.getUrlEncoder().encodeToString((accountName + ":" + plainTextPassword).getBytes(StandardCharsets.UTF_8));
            return authToken;

        } catch (JsonProcessingException ex) {
            throw new UserServiceException(FAILED_ACCOUNT_RETRIEVAL_MESSAGE);
        } catch (Exception e) {
            throw new UserServiceException(AUTH_TOKEN_GENERATION_MESSAGE);
        }
    }

    public void clearHash(String accountName) throws IOException {
        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getUserConfigName(), false);

        if (!internalUsersConfiguration.exists(accountName)) {
            throw new UserServiceException(FAILED_ACCOUNT_RETRIEVAL_MESSAGE);
        }

        JsonNode accountDetails = DefaultObjectMapper.readTree(internalUsersConfiguration.getCEntry(accountName).toString());
        final ObjectNode contentAsNode = (ObjectNode) accountDetails;
        SecurityJsonNode securityJsonNode = new SecurityJsonNode(contentAsNode);

        Optional.of(securityJsonNode.get("service"))
                .map(SecurityJsonNode::asString)
                .filter("true"::equalsIgnoreCase)
                .orElseThrow(() -> new UserServiceException(FAILED_CLEAR_HASH_MESSAGE));


        Optional.of(securityJsonNode.get("enabled"))
                .map(SecurityJsonNode::asString)
                .filter("true"::equalsIgnoreCase)
                .orElseThrow(() -> new UserServiceException(FAILED_CLEAR_HASH_MESSAGE));

        contentAsNode.remove("hash");
        contentAsNode.remove("name");
        internalUsersConfiguration.putCObject(accountName, DefaultObjectMapper.readTree(contentAsNode,  internalUsersConfiguration.getImplementingClass()));
        saveAndUpdateConfigs(getUserConfigName().toString(), client, CType.INTERNALUSERS, internalUsersConfiguration);
    }

    public void saveAndUpdateConfigs(final String indexName, final Client client, final CType cType, final SecurityDynamicConfiguration<?> configuration) {
        final IndexRequest ir = new IndexRequest(indexName);
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

    public SecurityDynamicConfiguration<?> geInternalUsersConfigurationRepository() {
        return load(getUserConfigName(), false);
    }
}
