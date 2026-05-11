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

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.action.apitokens.ApiToken;
import org.opensearch.security.http.ApiTokenAuthenticator;
import org.opensearch.test.framework.ApiTokenConfig;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public class ApiTokenTest {

    public static final String POINTER_USERNAME = "/user_name";

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);
    static final TestSecurityConfig.User REGULAR_USER = new TestSecurityConfig.User("regular_user");

    private static final String CREATE_API_TOKEN_PATH = "_plugins/_security/api/apitokens";
    public static final String ADMIN_USER_NAME = "admin";
    public static final String REGULAR_USER_NAME = "regular_user";
    public static final String DEFAULT_PASSWORD = "secret";
    public static final String NEW_PASSWORD = "testPassword123!!";
    public static final String TEST_TOKEN_PAYLOAD = """
        {
          "name": "test-token",
          "cluster_permissions": ["cluster_monitor"],
          "duration_seconds": 3600
        }
        """;

    public static final String TEST_TOKEN_WITH_INDEX_PERMISSIONS_PAYLOAD = """
        {
          "name": "test-token-index",
          "cluster_permissions": [],
          "index_permissions": [{
            "index_pattern": ["test-index-*"],
            "allowed_actions": ["indices:data/read/search"]
          }],
          "duration_seconds": 3600
        }
        """;

    public static final String TEST_TOKEN_INVALID_PAYLOAD = """
        {
          "name": "test-token",
          "cluster_permissions": ["cluster_monitor"],
          "duration_seconds": "wrong"
        }
        """;

    public static final String TEST_TOKEN_INVALID_PARAMETER_IN_PAYLOAD = """
        {
          "name": "test-token",
          "cluster_permissions": ["cluster_monitor"],
          "duration_seconds": 3600,
          "foo": "bar"
        }
        """;

    public static final String CURRENT_AND_NEW_PASSWORDS = "{ \"current_password\": \""
        + DEFAULT_PASSWORD
        + "\", \"password\": \""
        + NEW_PASSWORD
        + "\" }";

    private static ApiTokenConfig defaultApiTokenConfig() {
        return new ApiTokenConfig().enabled(true);
    }

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .users(ADMIN_USER, REGULAR_USER)
        .nodeSettings(
            Map.of(
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()),
                "plugins.security.unsupported.restapi.allow_securityconfig_modification",
                true
            )
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .apiToken(defaultApiTokenConfig())
        .build();

    @Before
    public void before() {
        patchApiTokenConfig(defaultApiTokenConfig());
        deleteAllApiTokens();
    }

    @Test
    public void testAuthInfoEndpoint() {
        String apiToken = generateApiToken(TEST_TOKEN_PAYLOAD);
        Header authHeader = new BasicHeader("Authorization", "ApiKey " + apiToken);
        authenticateWithApiToken(authHeader, HttpStatus.SC_OK);
    }

    @Test
    public void testDashboardsInfoReportsApiTokensEnabled() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.get("_plugins/_security/dashboardsinfo");
            assertThat(response, isOk());
            assertThat(response.getTextFromJsonBody("/api_tokens_enabled"), equalTo("true"));
            assertThat(response.getTextFromJsonBody("/max_duration_seconds"), equalTo("7776000"));
        }
    }

    @Test
    public void testCallingClusterHealthWithApiToken_success() {
        String apiToken = generateApiToken(TEST_TOKEN_PAYLOAD);
        Header authHeader = new BasicHeader("Authorization", "ApiKey " + apiToken);
        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.get("_cluster/health");
            response.assertStatusCode(HttpStatus.SC_OK);
        }
    }

    @Test
    public void shouldNotAuthenticateWithATamperedAPIToken() {
        String apiToken = generateApiToken(TEST_TOKEN_PAYLOAD);
        apiToken = apiToken.substring(0, apiToken.length() - 1); // tampering the token
        Header authHeader = new BasicHeader("Authorization", "ApiKey " + apiToken);
        authenticateWithApiToken(authHeader, HttpStatus.SC_UNAUTHORIZED);
    }

    @Test
    public void shouldNotBeAbleToUseTokenToGenerateMoreTokens() {
        String apiToken = generateApiToken(TEST_TOKEN_PAYLOAD);
        Header authHeader = new BasicHeader("Authorization", "ApiKey " + apiToken);

        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.postJson(CREATE_API_TOKEN_PATH, TEST_TOKEN_PAYLOAD);
            response.assertStatusCode(HttpStatus.SC_UNAUTHORIZED);
        }
    }

    @Test
    public void testAccountApiForbiddenWithApiToken() {
        String apiToken = generateApiToken(TEST_TOKEN_PAYLOAD);
        Header authHeader = new BasicHeader("Authorization", "ApiKey " + apiToken);

        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.putJson("_plugins/_security/api/account", CURRENT_AND_NEW_PASSWORDS);
            response.assertStatusCode(HttpStatus.SC_UNAUTHORIZED);
        }
    }

    @Test
    public void testRegularUserShouldNotBeAbleToGenerateApiToken() {
        try (TestRestClient client = cluster.getRestClient(REGULAR_USER)) {
            TestRestClient.HttpResponse response = client.postJson(CREATE_API_TOKEN_PATH, TEST_TOKEN_PAYLOAD);
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }
    }

    @Test
    public void shouldNotAuthenticateWithInvalidExpiration() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(CREATE_API_TOKEN_PATH, TEST_TOKEN_INVALID_PAYLOAD);
            response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(response.getTextFromJsonBody("/error"), containsString("failed to parse field [duration_seconds]"));
        }
    }

    @Test
    public void shouldNotAuthenticateWithInvalidAPIParameter() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(CREATE_API_TOKEN_PATH, TEST_TOKEN_INVALID_PARAMETER_IN_PAYLOAD);
            response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(response.getTextFromJsonBody("/error"), containsString("[create_api_token_request] unknown field [foo]"));
        }
    }

    @Test
    public void shouldNotAllowTokenWhenApiTokensAreDisabled() {
        final Header apiTokenHeader = new BasicHeader("Authorization", "ApiKey " + generateApiToken(TEST_TOKEN_PAYLOAD));
        authenticateWithApiToken(apiTokenHeader, HttpStatus.SC_OK);

        // Disable API Tokens via config and see that the authenticator doesn't authorize
        patchApiTokenConfig(defaultApiTokenConfig().enabled(false));
        authenticateWithApiToken(apiTokenHeader, HttpStatus.SC_UNAUTHORIZED);

        // Re-enable API Tokens via config and see that the authenticator is working again
        patchApiTokenConfig(defaultApiTokenConfig().enabled(true));
        authenticateWithApiToken(apiTokenHeader, HttpStatus.SC_OK);
    }

    @Test
    public void testApiTokenWithIndexPermissions_canSearchAllowedIndex() {
        // Create the allowed index as admin
        try (TestRestClient adminClient = cluster.getRestClient(ADMIN_USER)) {
            adminClient.putJson("test-index-allowed", "{\"settings\":{\"number_of_shards\":1}}").assertStatusCode(HttpStatus.SC_OK);
        }

        String apiToken = generateApiToken(TEST_TOKEN_WITH_INDEX_PERMISSIONS_PAYLOAD);
        Header authHeader = new BasicHeader("Authorization", "ApiKey " + apiToken);

        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            // Should be able to search the allowed index pattern
            TestRestClient.HttpResponse response = client.get("test-index-allowed/_search");
            response.assertStatusCode(HttpStatus.SC_OK);

            // Should NOT be able to search an index outside the allowed pattern
            TestRestClient.HttpResponse forbiddenResponse = client.get("other-index/_search");
            assertThat(forbiddenResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        }
    }

    @Test
    public void testApiTokenWithIndexPermissions_canWriteAllowedIndex() {
        try (TestRestClient adminClient = cluster.getRestClient(ADMIN_USER)) {
            adminClient.putJson("test-index-write", "{\"settings\":{\"number_of_shards\":1}}").assertStatusCode(HttpStatus.SC_OK);
        }

        String writePayload = """
            {
              "name": "test-token-index-write",
              "cluster_permissions": ["indices:data/write/bulk"],
              "index_permissions": [{
                "index_pattern": ["test-index-write"],
                "allowed_actions": ["indices:data/write/index", "indices:data/write/bulk*", "indices:admin/mapping/put"]
              }],
              "duration_seconds": 3600
            }
            """;
        String apiToken = generateApiToken(writePayload);
        Header authHeader = new BasicHeader("Authorization", "ApiKey " + apiToken);

        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.postJson("test-index-write/_doc", "{\"field\": \"value\"}");
            response.assertStatusCode(HttpStatus.SC_CREATED);

            TestRestClient.HttpResponse forbiddenResponse = client.postJson("other-index/_doc", "{\"field\": \"value\"}");
            assertThat(forbiddenResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        }
    }

    @Test
    public void testExpiredApiToken_isRejected() throws Exception {
        // Create a token with a 1-second expiration, then wait for it to expire
        String expiredPayload = """
            {
              "name": "expired-token",
              "cluster_permissions": ["cluster_monitor"],
              "duration_seconds": 1
            }
            """;
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(CREATE_API_TOKEN_PATH, expiredPayload);
            response.assertStatusCode(HttpStatus.SC_OK);
            String expiredToken = response.getTextFromJsonBody("/token").toString();
            Thread.sleep(1500); // Wait for token to expire
            Header authHeader = new BasicHeader("Authorization", "ApiKey " + expiredToken);
            authenticateWithApiToken(authHeader, HttpStatus.SC_UNAUTHORIZED);
        }
    }

    @Test
    public void testAdminCanRevokeTokenIssuedByAnotherUser() {
        // Create token and capture both the plaintext token and the doc id
        String apiToken;
        String tokenId;
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(CREATE_API_TOKEN_PATH, TEST_TOKEN_PAYLOAD);
            response.assertStatusCode(HttpStatus.SC_OK);
            apiToken = response.getTextFromJsonBody("/token");
            tokenId = response.getTextFromJsonBody("/id");
        }
        Header authHeader = new BasicHeader("Authorization", "ApiKey " + apiToken);

        // Token works before revocation
        authenticateWithApiToken(authHeader, HttpStatus.SC_OK);

        // Admin revokes by id
        try (TestRestClient adminClient = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse revokeResponse = adminClient.delete(CREATE_API_TOKEN_PATH + "/" + tokenId);
            revokeResponse.assertStatusCode(HttpStatus.SC_OK);
            assertThat(revokeResponse.getTextFromJsonBody("/message"), containsString("revoked successfully"));
        }

        // Token no longer works after revocation
        authenticateWithApiToken(authHeader, HttpStatus.SC_UNAUTHORIZED);
    }

    @Test
    public void testRevokedTokenAppearsInListWithRevokedAt() {
        String tokenId;
        try (TestRestClient adminClient = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse createResponse = adminClient.postJson(CREATE_API_TOKEN_PATH, TEST_TOKEN_PAYLOAD);
            createResponse.assertStatusCode(HttpStatus.SC_OK);
            tokenId = createResponse.getTextFromJsonBody("/id");
        }

        try (TestRestClient adminClient = cluster.getRestClient(ADMIN_USER)) {
            adminClient.delete(CREATE_API_TOKEN_PATH + "/" + tokenId).assertStatusCode(HttpStatus.SC_OK);
        }

        final String revokedId = tokenId;
        try (TestRestClient adminClient = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse listResponse = adminClient.get(CREATE_API_TOKEN_PATH);
            listResponse.assertStatusCode(HttpStatus.SC_OK);
            // Find our specific token in the list and verify it has revoked_at
            boolean found = false;
            for (tools.jackson.databind.JsonNode token : listResponse.bodyAsJsonNode()) {
                if (revokedId.equals(token.get(ApiToken.ID_FIELD).asText())) {
                    assertThat(token.has(ApiToken.REVOKED_AT_FIELD), equalTo(true));
                    found = true;
                    break;
                }
            }
            assertThat("Revoked token should appear in list", found, equalTo(true));
        }
    }

    private String generateApiToken(String payload) {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(CREATE_API_TOKEN_PATH, payload);
            response.assertStatusCode(HttpStatus.SC_OK);
            return response.getTextFromJsonBody("/token").toString();
        }
    }

    @Test
    public void testTokenNameMustBeValidFormat() {
        String payload = """
            {
              "name": "invalid name with spaces!",
              "cluster_permissions": ["cluster_monitor"],
              "duration_seconds": 3600
            }
            """;
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(CREATE_API_TOKEN_PATH, payload);
            response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(response.getTextFromJsonBody("/error"), containsString("alphanumeric"));
        }
    }

    @Test
    public void testTokenNameMustBeUnique() {
        generateApiToken(TEST_TOKEN_PAYLOAD);
        // Try to create another token with the same name
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(CREATE_API_TOKEN_PATH, TEST_TOKEN_PAYLOAD);
            response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(response.getTextFromJsonBody("/error"), containsString("already exists"));
        }
    }

    @Test
    public void testTokenExceedingMaxExpirationIsRejected() {
        // 90 days in ms = 7776000000, try 91 days
        String payload = """
            {
              "name": "too-long-token",
              "cluster_permissions": ["cluster_monitor"],
              "duration_seconds": 7862400
            }
            """;
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(CREATE_API_TOKEN_PATH, payload);
            response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(response.getTextFromJsonBody("/error"), containsString("exceeds the maximum allowed duration"));
        }
    }

    private void authenticateWithApiToken(Header authHeader, int expectedStatusCode) {
        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.getAuthInfo();
            response.assertStatusCode(expectedStatusCode);
            assertThat(response.getStatusCode(), equalTo(expectedStatusCode));
            if (expectedStatusCode == HttpStatus.SC_OK) {
                String username = response.getTextFromJsonBody(POINTER_USERNAME);
                assertThat(username, startsWith(ApiTokenAuthenticator.API_TOKEN_USER_PREFIX));
            }
        }
    }

    private void deleteAllApiTokens() {
        try (TestRestClient adminClient = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse listResponse = adminClient.get(CREATE_API_TOKEN_PATH);
            listResponse.assertStatusCode(HttpStatus.SC_OK);
            listResponse.bodyAsJsonNode().forEach(token -> {
                // Only revoke tokens that are not already revoked
                if (!token.has(ApiToken.REVOKED_AT_FIELD)) {
                    String id = token.get(ApiToken.ID_FIELD).asText();
                    adminClient.delete(CREATE_API_TOKEN_PATH + "/" + id).assertStatusCode(HttpStatus.SC_OK);
                }
            });
        }
    }

    private void patchApiTokenConfig(final ApiTokenConfig apiTokenConfig) {
        try (final TestRestClient adminClient = cluster.getRestClient(cluster.getAdminCertificate())) {
            final XContentBuilder configBuilder = XContentFactory.jsonBuilder();
            configBuilder.value(apiTokenConfig);

            final String patchBody = "[{ \"op\": \"replace\", \"path\": \"/config/dynamic/api_tokens\", \"value\":"
                + configBuilder.toString()
                + "}]";
            final var response = adminClient.patch("_plugins/_security/api/securityconfig", patchBody);
            response.assertStatusCode(HttpStatus.SC_OK);
        } catch (final IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
