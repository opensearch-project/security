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

public class ApiTokenRepository {
    private final ApiTokenIndexHandler apiTokenIndexHandler;

    public ApiTokenRepository(Client client, ClusterService clusterService) {
        apiTokenIndexHandler = new ApiTokenIndexHandler(client, clusterService);
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
        return apiTokenIndexHandler.indexTokenMetadata(new ApiToken(name, "test-token", clusterPermissions, indexPermissions, expiration));
    }

    public void deleteApiToken(String name) throws ApiTokenException, IndexNotFoundException {
        apiTokenIndexHandler.deleteToken(name);
    }

    public Map<String, ApiToken> getApiTokens() throws IndexNotFoundException {
        return apiTokenIndexHandler.getTokenMetadatas();
    }

}
