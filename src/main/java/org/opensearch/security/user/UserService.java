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
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.function.LongSupplier;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableList;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensaml.xmlsec.signature.P;
import org.opensearch.ExceptionsHelper;
import org.opensearch.action.ActionListener;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.authtoken.jwt.JwtVendor;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.api.AbstractApiAction;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.Hashed;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecurityJsonNode;

import static org.opensearch.security.dlic.rest.api.AbstractApiAction.saveAndUpdateConfigs;
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

    User tokenUser;
    final static String NO_PASSWORD_OR_HASH_MESSAGE = "Please specify either 'hash' or 'password' when creating a new internal user.";
    final static String RESTRICTED_CHARACTER_USE_MESSAGE = "A restricted character(s) was detected in the account name. Please remove: ";

    final static String SERVICE_ACCOUNT_PASSWORD_MESSAGE = "A password cannot be provided for a service account. Failed to register service account: ";

    final static String SERVICE_ACCOUNT_HASH_MESSAGE = "A password hash cannot be provided for service account. Failed to register service account: ";

    final static String NO_ACCOUNT_NAME_MESSAGE = "No account name was specified in the request.";

    final static String FAILED_ACCOUNT_RETRIEVAL_MESSAGE = "The account specified could not be accessed at this time.";
    final static String AUTH_TOKEN_GENERATION_MESSAGE = "An auth token could not be generated for the specified account.";
    private static CType getUserConfigName() {
        return CType.INTERNALUSERS;
    }

    private static CType getTokenConfigName() {
        return CType.TOKENS;
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

        // No one should be able to act as this user, so generate a random value and never store it
        AuthCredentials credentials = new AuthCredentials("tokenUser", new SecureRandom().toString().getBytes());
        this.tokenUser = new User("tokenUser", Collections.singleton("admin"), credentials); // TODO: Confirm this is proper
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

    /**
     * This function will handle the creation or update of a user account.
     *
     * @param accountDetailsAsString A string JSON of different account configurations.
     * @return InternalUserConfiguration with the new/updated user
     * @throws UserServiceException
     * @throws IOException
     */
    public SecurityDynamicConfiguration<?> createOrUpdateAccount(String accountDetailsAsString) throws IOException {

        ObjectMapper mapper = new ObjectMapper();
        JsonNode accountDetails = mapper.readTree(accountDetailsAsString);
        final ObjectNode contentAsNode = (ObjectNode) accountDetails;
        SecurityJsonNode securityJsonNode = new SecurityJsonNode(contentAsNode);

        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getUserConfigName(), false);
        String accountName = securityJsonNode.get("name").asString();

        if (accountName == null || accountName.length() == 0) { // Fail if field is present but empty
            throw new UserServiceException(NO_ACCOUNT_NAME_MESSAGE);
        }

        if (!securityJsonNode.get("attributes").get("owner").isNull() && !securityJsonNode.get("attributes").get("owner").asString().equals(accountName)) { // If this is a service account
            verifyServiceAccount(securityJsonNode, accountName);
            String password = generatePassword();
            contentAsNode.put("password", password);
            contentAsNode.put("hash", hash(password.toCharArray()));
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
            contentAsNode.put("hash", hash(plainTextPassword.toCharArray()));
        } else if (origHash != null && origHash.length() > 0) {
            contentAsNode.remove("password");
        } else if (plainTextPassword != null && plainTextPassword.isEmpty() && origHash == null) {
            contentAsNode.remove("password");
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
        String generatedPassword = "superSecurePassword";
        return generatedPassword;
    }

    /**
     * This function retrieves the auth token associated with a service account.
     * Fails if the provided account is not a service account or account is not enabled.
     *
     * @param accountName A string representing the name of the account
     * @return A string auth token
     */
    public SecurityDynamicConfiguration<?> generateAuthToken(String accountName) throws JsonProcessingException {

        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(getUserConfigName(), false);
        SecurityDynamicConfiguration<?> tokenConfiguration = load(getTokenConfigName(), false);

        if (!internalUsersConfiguration.exists(accountName)) {
            throw new UserServiceException(FAILED_ACCOUNT_RETRIEVAL_MESSAGE);
        }
        
        String authToken = null;
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode accountDetails = mapper.readTree(internalUsersConfiguration.getCEntry(accountName).toString());
            final ObjectNode contentAsNode = (ObjectNode) accountDetails;
            SecurityJsonNode securityJsonNode = new SecurityJsonNode(contentAsNode);

            if (securityJsonNode.get("attributes").get("owner").isNull()) { // If this is not a service account
                throw new UserServiceException(AUTH_TOKEN_GENERATION_MESSAGE);
            }
            if (securityJsonNode.get("attributes").get("owner").asString().equals(accountName)) { // If this is not a service account
                throw new UserServiceException(AUTH_TOKEN_GENERATION_MESSAGE);
            }
            if (securityJsonNode.get("attributes").get("isEnabled").asString().equals("false")) { // If the service account is not active
                throw new UserServiceException(AUTH_TOKEN_GENERATION_MESSAGE);
            }

            LongSupplier nanoClock = () -> System.nanoTime();
            JwtVendor vendor = new JwtVendor(this.client.settings(), nanoClock);
            authToken = vendor.createJwt(this.tokenUser.getName(), accountName, accountName, (int) nanoClock.getAsLong(), securityJsonNode.get("attributes").get("roles").asList());

            String oldToken = null;
            if (securityJsonNode.get("attributes").get("authtoken").isNull()) {
                contentAsNode.put("authtoken", authToken);
            } else {
                oldToken = contentAsNode.get("authtoken").toString();
                contentAsNode.remove("authtoken");
                contentAsNode.put("authtoken", authToken);
            }

            // Update the internal user associated with the auth token
            internalUsersConfiguration.remove(accountName);
            contentAsNode.remove("name");
            internalUsersConfiguration.putCObject(accountName, DefaultObjectMapper.readTree(contentAsNode,  internalUsersConfiguration.getImplementingClass()));
            saveAndUpdateConfigs(getUserConfigName().toString(), client, CType.INTERNALUSERS, internalUsersConfiguration);

            tokenConfiguration.remove(oldToken);
            tokenConfiguration.putCObject(authToken, accountName); // Makes a configuration entry of <String token, String accountName>
            return tokenConfiguration;

        } catch (JsonProcessingException ex) {
            throw new UserServiceException(FAILED_ACCOUNT_RETRIEVAL_MESSAGE);
        } catch (Exception e) {
            throw new UserServiceException(AUTH_TOKEN_GENERATION_MESSAGE);
        }
    }

    public static void saveAndUpdateConfigs(final String indexName, final Client client, final CType cType, final SecurityDynamicConfiguration<?> configuration) {
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
}
