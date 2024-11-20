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

public class ApiTokenRepository {
    private ApiTokenIndexHandler apiTokenIndexHandler;

    public ApiTokenRepository(Client client, ClusterService clusterService) {
        apiTokenIndexHandler = new ApiTokenIndexHandler(client, clusterService);
    }

    public String createApiToken(String name) {
        apiTokenIndexHandler.createApiTokenIndexIfAbsent();
        return apiTokenIndexHandler.indexToken(new ApiToken(name, "test-token", List.of()));
    }

    public void deleteApiToken(String name) throws ApiTokenException {
        apiTokenIndexHandler.createApiTokenIndexIfAbsent();
        apiTokenIndexHandler.deleteToken(name);
    }

    public List<Map<String, Object>> getApiTokens() {
        apiTokenIndexHandler.createApiTokenIndexIfAbsent();
        return apiTokenIndexHandler.getApiTokens();
    }

}
