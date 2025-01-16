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

package org.opensearch.security.action.apitokens;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.google.common.annotations.VisibleForTesting;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.security.authtoken.jwt.ExpiringBearerAuthToken;
import org.opensearch.security.identity.SecurityTokenManager;

public class ApiTokenRepository {
    private final ApiTokenIndexHandler apiTokenIndexHandler;
    private final SecurityTokenManager securityTokenManager;
    private static final Logger log = LogManager.getLogger(ApiTokenRepository.class);

    private final Map<String, Permissions> jtis = new ConcurrentHashMap<>();

    void reloadApiTokensFromIndex() {
        jtis.clear();
        Map<String, ApiToken> tokensFromIndex = apiTokenIndexHandler.getTokenMetadatas();
        tokensFromIndex.forEach(
            (key, apiToken) -> jtis.put(key, new Permissions(apiToken.getClusterPermissions(), apiToken.getIndexPermissions()))
        );
    }

    public Permissions getPermissionsForJti(String jti) {
        return jtis.get(jti);
    }

    // Method to check if a token is valid
    public boolean isValidToken(String jti) {
        return jtis.containsKey(jti);
    }

    public Map<String, Permissions> getJtis() {
        return jtis;
    }

    @Inject
    public ApiTokenRepository(Client client, ClusterService clusterService, SecurityTokenManager tokenManager) {
        apiTokenIndexHandler = new ApiTokenIndexHandler(client, clusterService);
        securityTokenManager = tokenManager;
    }

    private ApiTokenRepository(ApiTokenIndexHandler apiTokenIndexHandler, SecurityTokenManager securityTokenManager) {
        this.apiTokenIndexHandler = apiTokenIndexHandler;
        this.securityTokenManager = securityTokenManager;
    }

    @VisibleForTesting
    static ApiTokenRepository forTest(ApiTokenIndexHandler apiTokenIndexHandler, SecurityTokenManager securityTokenManager) {
        return new ApiTokenRepository(apiTokenIndexHandler, securityTokenManager);
    }

    public String createApiToken(
        String name,
        List<String> clusterPermissions,
        List<ApiToken.IndexPermission> indexPermissions,
        Long expiration
    ) {
        apiTokenIndexHandler.createApiTokenIndexIfAbsent();
        // TODO: Add validation on whether user is creating a token with a subset of their permissions
        ExpiringBearerAuthToken token = securityTokenManager.issueApiToken(name, expiration);
        ApiToken apiToken = new ApiToken(name, clusterPermissions, indexPermissions, expiration);
        apiTokenIndexHandler.indexTokenMetadata(apiToken);
        return token.getCompleteToken();
    }

    public void deleteApiToken(String name) throws ApiTokenException, IndexNotFoundException {
        apiTokenIndexHandler.deleteToken(name);
    }

    public Map<String, ApiToken> getApiTokens() throws IndexNotFoundException {
        return apiTokenIndexHandler.getTokenMetadatas();
    }

}
