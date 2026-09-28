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

import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
 * Verifies that API token endpoints return 403 when the feature is disabled (default).
 */
public class ApiTokenDisabledTest {

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    private static final String API_TOKEN_PATH = "_plugins/_security/api/apitokens";

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
        // Intentionally NOT setting .apiToken() — feature is disabled by default
        .build();

    @Test
    public void testCreateTokenReturns403WhenDisabled() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            String payload = """
                {
                  "name": "test-token",
                  "cluster_permissions": ["cluster_monitor"],
                  "index_permissions": [],
                  "expiration": "30d"
                }
                """;
            TestRestClient.HttpResponse response = client.postJson(API_TOKEN_PATH, payload);
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
            assertThat(response.getBody(), containsString("API tokens are not enabled"));
        }
    }

    @Test
    public void testGetTokensReturns403WhenDisabled() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.get(API_TOKEN_PATH);
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
            assertThat(response.getBody(), containsString("API tokens are not enabled"));
        }
    }

    @Test
    public void testDeleteTokenReturns403WhenDisabled() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.delete(API_TOKEN_PATH + "/some-id");
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
            assertThat(response.getBody(), containsString("API tokens are not enabled"));
        }
    }
}
