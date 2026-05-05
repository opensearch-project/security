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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;

import com.google.common.annotations.VisibleForTesting;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.security.configuration.TokenListener;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.User;
import org.opensearch.transport.client.Client;

import static org.opensearch.security.http.ApiTokenAuthenticator.API_TOKEN_USER_PREFIX;

public class ApiTokenRepository {
    public static final String TOKEN_PREFIX = "os_";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final ApiTokenIndexHandler apiTokenIndexHandler;
    private final List<TokenListener> tokenListener = new ArrayList<>();
    private static final Logger log = LogManager.getLogger(ApiTokenRepository.class);

    private final Map<String, RoleV7> tokenHashToRole = new ConcurrentHashMap<>();
    private final Map<String, Long> tokenHashToExpiration = new ConcurrentHashMap<>();

    public record TokenMetadata(RoleV7 role, long expiration) {
        public boolean isExpired() {
            return expiration > 0 && Instant.now().toEpochMilli() > expiration;
        }
    }

    public static String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static String generateToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return TOKEN_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public void reloadApiTokensFromIndex(ActionListener<Void> listener) {
        apiTokenIndexHandler.getTokenMetadatas(new ActionListener<Map<String, ApiToken>>() {
            @Override
            public void onResponse(Map<String, ApiToken> tokenMetadatas) {
                tokenHashToRole.keySet().removeIf(hash -> !tokenMetadatas.containsKey(hash));
                tokenHashToExpiration.keySet().removeIf(hash -> !tokenMetadatas.containsKey(hash));
                tokenMetadatas.forEach((hash, tokenMetadata) -> {
                    if (tokenMetadata.isRevoked()) {
                        tokenHashToRole.remove(hash);
                        tokenHashToExpiration.remove(hash);
                        return;
                    }
                    tokenHashToRole.put(hash, buildRole(tokenMetadata));
                    tokenHashToExpiration.put(hash, tokenMetadata.getExpiration());
                });
                listener.onResponse(null);
            }

            @Override
            public void onFailure(Exception e) {
                if (ExceptionsHelper.unwrapCause(e) instanceof IndexNotFoundException) {
                    log.debug("API tokens index does not exist yet, skipping reload");
                    listener.onResponse(null);
                    return;
                }
                listener.onFailure(new OpenSearchSecurityException("Received error while reloading API tokens metadata from index", e));
            }
        });
    }

    private static RoleV7 buildRole(ApiToken tokenMetadata) {
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
        return role;
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
            String hash = name.substring(API_TOKEN_USER_PREFIX.length());
            if (isValidToken(hash)) {
                return getPermissionsForHash(hash);
            }
        }
        return new RoleV7();
    }

    public RoleV7 getPermissionsForHash(String hash) {
        return tokenHashToRole.get(hash);
    }

    public TokenMetadata getTokenMetadata(String hash) {
        RoleV7 role = tokenHashToRole.get(hash);
        Long expiration = tokenHashToExpiration.get(hash);
        if (role == null || expiration == null) {
            return null;
        }
        return new TokenMetadata(role, expiration);
    }

    public boolean isValidToken(String hash) {
        return tokenHashToRole.containsKey(hash);
    }

    public void forEachToken(BiConsumer<String, RoleV7> consumer) {
        tokenHashToRole.forEach((hash, role) -> consumer.accept(API_TOKEN_USER_PREFIX + hash, role));
    }

    @VisibleForTesting
    Map<String, RoleV7> getTokenHashToRole() {
        return tokenHashToRole;
    }

    public ApiTokenRepository(Client client, ClusterService clusterService) {
        apiTokenIndexHandler = new ApiTokenIndexHandler(client, clusterService);
    }

    private ApiTokenRepository(ApiTokenIndexHandler apiTokenIndexHandler) {
        this.apiTokenIndexHandler = apiTokenIndexHandler;
    }

    @VisibleForTesting
    static ApiTokenRepository forTest(ApiTokenIndexHandler apiTokenIndexHandler) {
        return new ApiTokenRepository(apiTokenIndexHandler);
    }

    public record TokenCreated(String id, String token) {
    }

    public void createApiToken(
        String name,
        List<String> clusterPermissions,
        List<ApiToken.IndexPermission> indexPermissions,
        Long expiration,
        String createdBy,
        ActionListener<TokenCreated> listener
    ) {
        String plaintext = generateToken();
        String hash = hashToken(plaintext);
        ApiToken apiToken = new ApiToken(name, hash, clusterPermissions, indexPermissions, Instant.now(), expiration, null, createdBy);
        apiTokenIndexHandler.createApiTokenIndexIfAbsent(ActionListener.wrap(() -> {
            apiTokenIndexHandler.indexTokenMetadata(apiToken, ActionListener.wrap(id -> {
                tokenHashToRole.put(hash, buildRole(apiToken));
                tokenHashToExpiration.put(hash, expiration);
                listener.onResponse(new TokenCreated(id, plaintext));
            }, listener::onFailure));
        }));
    }

    public void revokeApiToken(String id, ActionListener<Void> listener) throws OpenSearchSecurityException, IndexNotFoundException {
        apiTokenIndexHandler.revokeToken(id, listener);
    }

    public void getApiTokens(ActionListener<Map<String, ApiToken>> listener) {
        apiTokenIndexHandler.getTokenMetadatas(ActionListener.wrap(listener::onResponse, e -> {
            if (ExceptionsHelper.unwrapCause(e) instanceof IndexNotFoundException) {
                listener.onResponse(Map.of());
            } else {
                listener.onFailure(e);
            }
        }));
    }

    public void getTokenCount(ActionListener<Long> listener) {
        getApiTokens(ActionListener.wrap(tokens -> listener.onResponse((long) tokens.size()), listener::onFailure));
    }
}
