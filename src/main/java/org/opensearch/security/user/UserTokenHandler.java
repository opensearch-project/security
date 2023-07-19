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

import com.amazon.dlic.auth.http.jwt.keybyoidc.JwtVerifier;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.opensearch.ExceptionsHelper;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.BearerAuthToken;
import org.opensearch.security.authtoken.jwt.JwtVendor;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;

public class UserTokenHandler {

    private final int DEFAULT_EXPIRATION_TIME_SECONDS = 300;
    JwtVendor jwtVendor;
    Settings settings;

    ClusterService clusterService;

    ConfigurationRepository configurationRepository;

    ThreadPool threadPool;

    JwtVerifier jwtVerifier;

    String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);

    String signingKey = RandomStringUtils.randomAlphanumeric(16);

    Client client;

    final static String FAILED_CLEAR_HASH_MESSAGE = "The hash could not be cleared from the specified account.";

    public static CType getRevokedTokensConfigName() {
        return CType.REVOKEDTOKENS;
    }

    @Inject
    public UserTokenHandler(
        ThreadPool threadPool,
        ClusterService clusterService,
        ConfigurationRepository configurationRepository,
        Client client
    ) {
        this.settings = Settings.builder().put("signing_key", signingKey).put("encryption_key", claimsEncryptionKey).build();
        this.jwtVendor = new JwtVendor(settings, null);
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.client = client;
        this.configurationRepository = configurationRepository;
    }

    public AuthToken issueToken(String audience) {
        ThreadContext threadContext = threadPool.getThreadContext();
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        String jwt = null;
        try {
            jwt = jwtVendor.createJwt(
                clusterService.getClusterName().toString(),
                user.getName(),
                audience,
                DEFAULT_EXPIRATION_TIME_SECONDS,
                new ArrayList<String>(user.getRoles()),
                null
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return new BearerAuthToken(jwt);
    }

    public boolean validateToken(AuthToken authToken) {
        if (!(authToken instanceof BearerAuthToken)) {
            throw new UserServiceException("The provided token is not a BearerAuthToken.");
        }
        BearerAuthToken bearerAuthToken = (BearerAuthToken) authToken;
        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(bearerAuthToken.getCompleteToken());
        JwtToken jwt = jwtConsumer.getJwtToken();

        Long iat = (Long) jwt.getClaim("iat");
        Long exp = (Long) jwt.getClaim("exp");
        SecurityDynamicConfiguration revokedTokens = load(getRevokedTokensConfigName(), false);
        Long currentTime = System.currentTimeMillis();
        return (exp > currentTime && !revokedTokens.exists(bearerAuthToken.getCompleteToken()));
    }

    public String getTokenInfo(AuthToken authToken) {
        if (!(authToken instanceof BearerAuthToken)) {
            throw new UserServiceException("The provided token is not a BearerAuthToken.");
        }
        BearerAuthToken bearerAuthToken = (BearerAuthToken) authToken;
        return "The provided token is a BearerAuthToken with content: " + bearerAuthToken;
    }

    public void revokeToken(AuthToken authToken) {
        if (!(authToken instanceof BearerAuthToken)) {
            throw new UserServiceException("The provided token is not a BearerAuthToken.");
        }
        BearerAuthToken bearerAuthToken = (BearerAuthToken) authToken;
        SecurityDynamicConfiguration revokedTokens = load(getRevokedTokensConfigName(), false);
        revokedTokens.putCObject(bearerAuthToken.getCompleteToken(), bearerAuthToken);
        saveAndUpdateConfigs(getRevokedTokensConfigName().toString(), client, CType.REVOKEDTOKENS, revokedTokens);
    }

    /**
     * Load data for a given CType
     * @param config CType whose data is to be loaded in-memory
     * @return configuration loaded with given CType data
     */
    public SecurityDynamicConfiguration<?> load(final CType config, boolean logComplianceEvent) {
        SecurityDynamicConfiguration<?> loaded = configurationRepository.getConfigurationsFromIndex(
            Collections.singleton(config),
            logComplianceEvent
        ).get(config).deepClone();
        return DynamicConfigFactory.addStatics(loaded);
    }

    public void saveAndUpdateConfigs(
        final String indexName,
        final Client client,
        final CType cType,
        final SecurityDynamicConfiguration<?> configuration
    ) {
        final IndexRequest ir = new IndexRequest(indexName);
        final String id = cType.toLCString();

        configuration.removeStatic();

        try {
            client.index(
                ir.id(id)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .setIfSeqNo(configuration.getSeqNo())
                    .setIfPrimaryTerm(configuration.getPrimaryTerm())
                    .source(id, XContentHelper.toXContent(configuration, XContentType.JSON, false))
            );
        } catch (IOException e) {
            throw ExceptionsHelper.convertToOpenSearchException(e);
        }
    }
}
