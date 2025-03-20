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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

import com.google.common.annotations.VisibleForTesting;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.security.authtoken.jwt.ExpiringBearerAuthToken;
import org.opensearch.security.identity.SecurityTokenManager;
import org.opensearch.security.user.User;
import org.opensearch.transport.client.Client;

import static org.opensearch.security.http.ApiTokenAuthenticator.API_TOKEN_USER_PREFIX;

public class ApiTokenRepository {
    private final ApiTokenIndexHandler apiTokenIndexHandler;
    private final SecurityTokenManager securityTokenManager;
    private static final Logger log = LogManager.getLogger(ApiTokenRepository.class);

    private final Map<String, Permissions> jtis = new ConcurrentHashMap<>();

    void reloadApiTokensFromIndex() {
        CompletableFuture<Map<String, ApiToken>> future = new CompletableFuture<>();

        apiTokenIndexHandler.getTokenMetadatas(new ActionListener<Map<String, ApiToken>>() {
            @Override
            public void onResponse(Map<String, ApiToken> tokensFromIndex) {
                future.complete(tokensFromIndex);
            }

            @Override
            public void onFailure(Exception e) {
                future.completeExceptionally(e);
            }
        });

        future.thenAccept(tokensFromIndex -> {
            jtis.keySet().removeIf(key -> !tokensFromIndex.containsKey(key));
            tokensFromIndex.forEach(
                (key, apiToken) -> jtis.put(key, new Permissions(apiToken.getClusterPermissions(), apiToken.getIndexPermissions()))
            );
        });
    }

    public Permissions getApiTokenPermissionsForUser(User user) {
        String name = user.getName();
        if (name.startsWith(API_TOKEN_USER_PREFIX)) {
            String jti = user.getName().split(API_TOKEN_USER_PREFIX)[1];
            if (isValidToken(jti)) {
                return getPermissionsForJti(jti);
            }
        }
        return new Permissions(List.of(), List.of());
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

    public void createApiToken(
        String name,
        List<String> clusterPermissions,
        List<ApiToken.IndexPermission> indexPermissions,
        Long expiration,
        ActionListener<String> listener
    ) {
        apiTokenIndexHandler.createApiTokenIndexIfAbsent();
        ExpiringBearerAuthToken token = securityTokenManager.issueApiToken(name, expiration);
        ApiToken apiToken = new ApiToken(name, clusterPermissions, indexPermissions, expiration);
        apiTokenIndexHandler.indexTokenMetadata(
            apiToken,
            ActionListener.wrap(unused -> listener.onResponse(token.getCompleteToken()), exception -> listener.onFailure(exception))
        );
    }

    public void deleteApiToken(String name, ActionListener<Void> listener) throws ApiTokenException, IndexNotFoundException {
        apiTokenIndexHandler.deleteToken(name, listener);
    }

    public void getApiTokens(ActionListener<Map<String, ApiToken>> listener) {
        apiTokenIndexHandler.getTokenMetadatas(listener);
    }

    public void getTokenCount(ActionListener<Long> listener) {
        getApiTokens(ActionListener.wrap(tokens -> listener.onResponse((long) tokens.size()), listener::onFailure));
    }

}
