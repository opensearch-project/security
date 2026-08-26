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
 * Runs key API token scenarios with V4 (nextgen) privilege evaluation mode enabled.
 */
public class ApiTokenV4Test {

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    private static final String API_TOKEN_PATH = "_plugins/_security/api/apitokens";
    private static final String TOKEN_PAYLOAD = """
        {
          "name": "v4-test-token",
          "cluster_permissions": ["cluster_monitor"],
          "duration_seconds": 3600
        }
        """;
    private static final String INDEX_TOKEN_PAYLOAD = """
        {
          "name": "v4-index-token",
          "cluster_permissions": [],
          "index_permissions": [{
            "index_pattern": ["v4-test-*"],
            "allowed_actions": ["indices:data/read/search"]
          }],
          "duration_seconds": 3600
        }
        """;

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .users(ADMIN_USER)
        .nodeSettings(
            Map.of(
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()),
                "plugins.security.unsupported.restapi.allow_securityconfig_modification",
                true
            )
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .apiToken(new ApiTokenConfig().enabled(true))
        .privilegesEvaluationType("v4")
        .build();

    @Test
    public void testClusterPermissionWithV4() {
        String token = createToken(TOKEN_PAYLOAD);
        Header authHeader = new BasicHeader("Authorization", "ApiKey " + token);
        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.get("_cluster/health");
            response.assertStatusCode(HttpStatus.SC_OK);
        }
    }

    @Test
    public void testIndexPermissionAllowedWithV4() {
        try (TestRestClient adminClient = cluster.getRestClient(ADMIN_USER)) {
            adminClient.putJson("v4-test-allowed", "{\"settings\":{\"number_of_shards\":1}}").assertStatusCode(HttpStatus.SC_OK);
        }

        String token = createToken(INDEX_TOKEN_PAYLOAD);
        Header authHeader = new BasicHeader("Authorization", "ApiKey " + token);
        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.get("v4-test-allowed/_search");
            response.assertStatusCode(HttpStatus.SC_OK);
        }
    }

    @Test
    public void testIndexPermissionDeniedWithV4() {
        String payload = """
            {
              "name": "v4-index-token-denied",
              "cluster_permissions": [],
              "index_permissions": [{
                "index_pattern": ["v4-test-*"],
                "allowed_actions": ["indices:data/read/search"]
              }],
              "duration_seconds": 3600
            }
            """;
        String token = createToken(payload);
        Header authHeader = new BasicHeader("Authorization", "ApiKey " + token);
        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.get("other-index/_search");
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        }
    }

    private String createToken(String payload) {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(API_TOKEN_PATH, payload);
            response.assertStatusCode(HttpStatus.SC_OK);
            return response.getTextFromJsonBody("/token");
        }
    }
}
