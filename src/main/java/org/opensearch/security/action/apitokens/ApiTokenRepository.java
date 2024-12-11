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
import org.opensearch.security.securityconf.impl.v7.RoleV7;

public class ApiTokenRepository {
    private ApiTokenIndexHandler apiTokenIndexHandler;

    public ApiTokenRepository(Client client, ClusterService clusterService) {
        apiTokenIndexHandler = new ApiTokenIndexHandler(client, clusterService);
    }

    public String createApiToken(String name, List<String> clusterPermissions, List<RoleV7.Index> indexPermissions) {
        apiTokenIndexHandler.createApiTokenIndexIfAbsent();
        // TODO: Implement logic of creating JTI to match against during authc/z
        return apiTokenIndexHandler.indexToken(new ApiToken(name, "test-token", clusterPermissions, indexPermissions));
    }

    public void deleteApiToken(String name) throws ApiTokenException {
        apiTokenIndexHandler.createApiTokenIndexIfAbsent();
        apiTokenIndexHandler.deleteToken(name);
    }

    public Map<String, ApiToken> getApiTokens() {
        apiTokenIndexHandler.createApiTokenIndexIfAbsent();
        return apiTokenIndexHandler.getApiTokens();
    }

}
