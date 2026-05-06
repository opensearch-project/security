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

package org.opensearch.security.privileges;

import java.util.List;
import java.util.Map;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.test.framework.ApiTokenConfig;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
 * Verifies that API tokens cannot access protected indices even with wildcard permissions.
 */
public class ApiTokenProtectedIndicesTest {

    static final TestSecurityConfig.Role PROTECTED_INDEX_ROLE = new TestSecurityConfig.Role("protected_role");

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS)
        .referencedRoles(PROTECTED_INDEX_ROLE);

    private static final String API_TOKEN_PATH = "_plugins/_security/api/apitokens";

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .users(ADMIN_USER)
        .roles(PROTECTED_INDEX_ROLE)
        .nodeSettings(
            Map.of(
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()),
                "plugins.security.unsupported.restapi.allow_securityconfig_modification",
                true,
                "plugins.security.protected_indices.enabled",
                true,
                "plugins.security.protected_indices.indices",
                "protected-*",
                "plugins.security.protected_indices.roles",
                "protected_role"
            )
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .apiToken(new ApiTokenConfig().enabled(true))
        .privilegesEvaluationType("v4")
        .build();

    @Test
    public void testApiTokenCannotAccessProtectedIndex() {
        // Create the protected index as admin
        try (TestRestClient adminClient = cluster.getRestClient(ADMIN_USER)) {
            adminClient.putJson("protected-secret", "{\"settings\":{\"number_of_shards\":1}}").assertStatusCode(HttpStatus.SC_OK);
        }

        // Create a token with wildcard index permissions
        String payload = """
            {
              "name": "wildcard-token",
              "cluster_permissions": [],
              "index_permissions": [{
                "index_pattern": ["*"],
                "allowed_actions": ["indices:data/read/search"]
              }],
              "expiration": 3600000
            }
            """;
        String token;
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(API_TOKEN_PATH, payload);
            response.assertStatusCode(HttpStatus.SC_OK);
            token = response.getTextFromJsonBody("/token");
        }

        // Token should be denied access to the protected index
        Header authHeader = new BasicHeader("Authorization", "ApiKey " + token);
        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.get("protected-secret/_search");
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        }
    }

    @Test
    public void testApiTokenCanAccessNonProtectedIndex() {
        // Create a non-protected index
        try (TestRestClient adminClient = cluster.getRestClient(ADMIN_USER)) {
            adminClient.putJson("normal-index", "{\"settings\":{\"number_of_shards\":1}}").assertStatusCode(HttpStatus.SC_OK);
        }

        String payload = """
            {
              "name": "normal-token",
              "cluster_permissions": [],
              "index_permissions": [{
                "index_pattern": ["normal-*"],
                "allowed_actions": ["indices:data/read/search"]
              }],
              "expiration": 3600000
            }
            """;
        String token;
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(API_TOKEN_PATH, payload);
            response.assertStatusCode(HttpStatus.SC_OK);
            token = response.getTextFromJsonBody("/token");
        }

        Header authHeader = new BasicHeader("Authorization", "ApiKey " + token);
        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.get("normal-index/_search");
            response.assertStatusCode(HttpStatus.SC_OK);
        }
    }
}
