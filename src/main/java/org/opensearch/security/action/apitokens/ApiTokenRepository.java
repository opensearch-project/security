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

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.security.authtoken.jwt.ExpiringBearerAuthToken;
import org.opensearch.security.identity.SecurityTokenManager;

public class ApiTokenRepository {
    private final ApiTokenIndexHandler apiTokenIndexHandler;
    private final SecurityTokenManager securityTokenManager;

    public ApiTokenRepository(Client client, ClusterService clusterService, SecurityTokenManager tokenManager) {
        apiTokenIndexHandler = new ApiTokenIndexHandler(client, clusterService);
        securityTokenManager = tokenManager;
    }

    public String createApiToken(
        String name,
        List<String> clusterPermissions,
        List<ApiToken.IndexPermission> indexPermissions,
        Long expiration
    ) {
        apiTokenIndexHandler.createApiTokenIndexIfAbsent();
        // TODO: Implement logic of creating JTI to match against during authc/z
        // TODO: Add validation on whether user is creating a token with a subset of their permissions
        ApiToken apiToken = new ApiToken(name, clusterPermissions, indexPermissions, expiration);
        ExpiringBearerAuthToken token = securityTokenManager.issueApiToken(apiToken);
        apiToken.setJti(token.getCompleteToken());
        return apiTokenIndexHandler.indexTokenMetadata(apiToken);
    }

    public void deleteApiToken(String name) throws ApiTokenException, IndexNotFoundException {
        apiTokenIndexHandler.deleteToken(name);
    }

    public Map<String, ApiToken> getApiTokens() throws IndexNotFoundException {
        return apiTokenIndexHandler.getTokenMetadatas();
    }

}
