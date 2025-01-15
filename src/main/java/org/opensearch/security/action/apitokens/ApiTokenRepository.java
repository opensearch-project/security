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
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.security.authtoken.jwt.ExpiringBearerAuthToken;
import org.opensearch.security.identity.SecurityTokenManager;
import org.opensearch.security.support.ConfigConstants;

import static org.opensearch.security.action.apitokens.ApiToken.NAME_FIELD;

public class ApiTokenRepository implements ClusterStateListener {
    private final ApiTokenIndexHandler apiTokenIndexHandler;
    private final SecurityTokenManager securityTokenManager;
    private static final Logger log = LogManager.getLogger(ApiTokenRepository.class);

    private final Map<String, Permissions> jtis = new ConcurrentHashMap<>();

    private Client client;

    void reloadApiTokensFromIndex() {
        log.info("Reloading api tokens from index. Currnet entries: " + jtis.entrySet());
        try {
            jtis.clear();
            client.prepareSearch(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)
                .setQuery(QueryBuilders.matchAllQuery())
                .execute()
                .actionGet()
                .getHits()
                .forEach(hit -> {
                    // Parse the document and update the cache
                    Map<String, Object> source = hit.getSourceAsMap();
                    String jti = (String) source.get(NAME_FIELD);
                    Permissions permissions = parsePermissions(source);
                    jtis.put(jti, permissions);
                });
        } catch (Exception e) {
            log.error("Failed to reload API tokens cache", e);
        }
    }

    @SuppressWarnings("unchecked")
    private Permissions parsePermissions(Map<String, Object> source) {
        return new Permissions(
            (List<String>) source.get(ApiToken.CLUSTER_PERMISSIONS_FIELD),
            (List<ApiToken.IndexPermission>) source.get(ApiToken.INDEX_PERMISSIONS_FIELD)
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
        this.client = client;
        clusterService.addListener(this);
    }

    private ApiTokenRepository(ApiTokenIndexHandler apiTokenIndexHandler, SecurityTokenManager securityTokenManager, Client client) {
        this.apiTokenIndexHandler = apiTokenIndexHandler;
        this.securityTokenManager = securityTokenManager;
        this.client = client;
    }

    @VisibleForTesting
    static ApiTokenRepository forTest(ApiTokenIndexHandler apiTokenIndexHandler, SecurityTokenManager securityTokenManager, Client client) {
        return new ApiTokenRepository(apiTokenIndexHandler, securityTokenManager, client);
    }

    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        // Reload cache if the security index has changed
        IndexMetadata securityIndex = event.state().metadata().index(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX);
        if (securityIndex != null) {
            reloadApiTokensFromIndex();
        }
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
