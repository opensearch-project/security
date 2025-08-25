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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.google.common.annotations.VisibleForTesting;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.security.authtoken.jwt.ExpiringBearerAuthToken;
import org.opensearch.security.configuration.TokenListener;
import org.opensearch.security.identity.SecurityTokenManager;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.User;
import org.opensearch.transport.client.Client;

import static org.opensearch.security.http.ApiTokenAuthenticator.API_TOKEN_USER_PREFIX;

public class ApiTokenRepository {
    private final ApiTokenIndexHandler apiTokenIndexHandler;
    private final SecurityTokenManager securityTokenManager;
    private final List<TokenListener> tokenListener = new ArrayList<>();
    private static final Logger log = LogManager.getLogger(ApiTokenRepository.class);

    private final Map<String, RoleV7> jtis = new ConcurrentHashMap<>();

    void reloadApiTokensFromIndex(ActionListener<Void> listener) {
        apiTokenIndexHandler.getTokenMetadatas(new ActionListener<Map<String, ApiToken>>() {
            @Override
            public void onResponse(Map<String, ApiToken> tokenMetadatas) {
                jtis.keySet().removeIf(key -> !tokenMetadatas.containsKey(key));
                tokenMetadatas.forEach((key, tokenMetadata) -> {
                    RoleV7 role = new RoleV7();
                    role.setCluster_permissions(tokenMetadata.getClusterPermissions());
                    List<RoleV7.Index> indexPerms = new ArrayList<>();
                    for (ApiToken.IndexPermission ip : tokenMetadata.getIndexPermissions()) {
                        RoleV7.Index indexPerm = new RoleV7.Index();
                        indexPerm.setIndex_patterns(ip.getIndexPatterns());
                        indexPerm.setAllowed_actions(ip.getAllowedActions());
                        indexPerms.add(indexPerm);
                    }
                    role.setIndex_permissions(indexPerms);
                    jtis.put(key, role);
                    listener.onResponse(null);
                });
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(new OpenSearchSecurityException("Received error while reloading API tokens metadata from index", e));
            }
        });
    }

    public synchronized void subscribeOnChange(TokenListener listener) {
        tokenListener.add(listener);
    }

    public synchronized void notifyAboutChanges() {
        for (TokenListener listener : tokenListener) {
            try {
                log.debug("Notify {} listener about change", listener);
                listener.onChange();
            } catch (Exception e) {
                log.error("{} listener errored: " + e, listener, e);
                throw ExceptionsHelper.convertToOpenSearchException(e);
            }
        }
    }

    public RoleV7 getApiTokenPermissionsForUser(User user) {
        String name = user.getName();
        if (name.startsWith(API_TOKEN_USER_PREFIX)) {
            String jti = user.getName().split(API_TOKEN_USER_PREFIX)[1];
            if (isValidToken(jti)) {
                return getPermissionsForJti(jti);
            }
        }
        return new RoleV7();
    }

    public RoleV7 getPermissionsForJti(String jti) {
        return jtis.get(jti);
    }

    // Method to check if a token is valid
    public boolean isValidToken(String jti) {
        return jtis.containsKey(jti);
    }

    public Map<String, RoleV7> getJtis() {
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
        apiTokenIndexHandler.createApiTokenIndexIfAbsent(ActionListener.wrap(() -> {
            ExpiringBearerAuthToken token = securityTokenManager.issueApiToken(name, expiration);
            ApiToken apiToken = new ApiToken(name, clusterPermissions, indexPermissions, Instant.now(), expiration);
            apiTokenIndexHandler.indexTokenMetadata(
                apiToken,
                ActionListener.wrap(unused -> { listener.onResponse(token.getCompleteToken()); }, listener::onFailure)
            );
        }));

    }

    public void deleteApiToken(String name, ActionListener<Void> listener) throws ApiTokenException, IndexNotFoundException {
        apiTokenIndexHandler.deleteToken(name, listener);
    }

    public void getApiTokens(ActionListener<Map<String, ApiToken>> listener) {
        apiTokenIndexHandler.createApiTokenIndexIfAbsent(ActionListener.wrap(() -> { apiTokenIndexHandler.getTokenMetadatas(listener); }));

    }

    public void getTokenCount(ActionListener<Long> listener) {
        getApiTokens(ActionListener.wrap(tokens -> listener.onResponse((long) tokens.size()), listener::onFailure));
    }

}
