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
import java.nio.charset.StandardCharsets;
import java.util.Base64;
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
import org.opensearch.test.framework.ApiTokenConfig;
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

public class ApiTokenTest {

    public static final String POINTER_USERNAME = "/user_name";

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);
    static final TestSecurityConfig.User REGULAR_USER = new TestSecurityConfig.User("regular_user");

    private static final String CREATE_API_TOKEN_PATH = "_plugins/_security/api/apitokens";
    private static final String signingKey = Base64.getEncoder()
        .encodeToString(
            "jwt signing key for api token authentication backend for testing of API Token authentication".getBytes(StandardCharsets.UTF_8)
        );
    private static final String alternativeSigningKey = Base64.getEncoder()
        .encodeToString(
            "alternativeSigningKeyalternativeSigningKeyalternativeSigningKeyalternativeSigningKey".getBytes(StandardCharsets.UTF_8)
        );

    public static final String ADMIN_USER_NAME = "admin";
    public static final String REGULAR_USER_NAME = "regular_user";
    public static final String DEFAULT_PASSWORD = "secret";
    public static final String NEW_PASSWORD = "testPassword123!!";
    public static final String TEST_TOKEN_SUBJECT = "token:test-token";
    public static final String TEST_TOKEN_PAYLOAD = """
        {
          "name": "test-token",
          "cluster_permissions": ["cluster_monitor"]
        }
        """;

    public static final String TEST_TOKEN_WITH_INDEX_PERMISSIONS_PAYLOAD = """
        {
          "name": "test-token-index",
          "cluster_permissions": [],
          "index_permissions": [{
            "index_pattern": ["test-index-*"],
            "allowed_actions": ["indices:data/read/search"]
          }]
        }
        """;

    public static final String TEST_TOKEN_INVALID_PAYLOAD = """
        {
          "name": "test-token",
          "cluster_permissions": ["cluster_monitor"],
          "expiration": "wrong"
        }
        """;

    public static final String TEST_TOKEN_INVALID_PARAMETER_IN_PAYLOAD = """
        {
          "name": "test-token",
          "cluster_permissions": ["cluster_monitor"],
          "foo": "bar"
        }
        """;

    public static final String CURRENT_AND_NEW_PASSWORDS = "{ \"current_password\": \""
        + DEFAULT_PASSWORD
        + "\", \"password\": \""
        + NEW_PASSWORD
        + "\" }";

    private static ApiTokenConfig defaultApiTokenConfig() {
        return new ApiTokenConfig().enabled(true).signingKey(signingKey);
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
    }

    @Test
    public void testAuthInfoEndpoint() {
        String apiToken = generateApiToken(TEST_TOKEN_PAYLOAD);
        Header authHeader = new BasicHeader("Authorization", "Bearer " + apiToken);
        authenticateWithApiToken(authHeader, HttpStatus.SC_OK);
    }

    @Test
    public void testCallingClusterHealthWithApiToken_success() {
        String apiToken = generateApiToken(TEST_TOKEN_PAYLOAD);
        Header authHeader = new BasicHeader("Authorization", "Bearer " + apiToken);
        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.get("_cluster/health");
            response.assertStatusCode(HttpStatus.SC_OK);
        }
    }

    @Test
    public void shouldNotAuthenticateWithATamperedAPIToken() {
        String apiToken = generateApiToken(TEST_TOKEN_PAYLOAD);
        apiToken = apiToken.substring(0, apiToken.length() - 1); // tampering the token
        Header authHeader = new BasicHeader("Authorization", "Bearer " + apiToken);
        authenticateWithApiToken(authHeader, HttpStatus.SC_UNAUTHORIZED);
    }

    @Test
    public void shouldNotBeAbleToUseTokenToGenerateMoreTokens() {
        String apiToken = generateApiToken(TEST_TOKEN_PAYLOAD);
        Header authHeader = new BasicHeader("Authorization", "Bearer " + apiToken);

        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.postJson(CREATE_API_TOKEN_PATH, TEST_TOKEN_PAYLOAD);
            response.assertStatusCode(HttpStatus.SC_UNAUTHORIZED);
        }
    }

    @Test
    public void testAccountApiForbiddenWithApiToken() {
        String apiToken = generateApiToken(TEST_TOKEN_PAYLOAD);
        Header authHeader = new BasicHeader("Authorization", "Bearer " + apiToken);

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
            assertThat(response.getTextFromJsonBody("/error"), containsString("failed to parse field [expiration]"));
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
        final Header apiTokenHeader = new BasicHeader("Authorization", "Bearer " + generateApiToken(TEST_TOKEN_PAYLOAD));
        authenticateWithApiToken(apiTokenHeader, HttpStatus.SC_OK);

        // Disable API Tokens via config and see that the authenticator doesn't authorize
        patchApiTokenConfig(defaultApiTokenConfig().enabled(false));
        authenticateWithApiToken(apiTokenHeader, HttpStatus.SC_UNAUTHORIZED);

        // Re-enable API Tokens via config and see that the authenticator is working again
        patchApiTokenConfig(defaultApiTokenConfig().enabled(true));
        authenticateWithApiToken(apiTokenHeader, HttpStatus.SC_OK);
    }

    @Test
    public void apiTokenSigningCheckChangeIsDetected() {
        final Header apiTokenOriginalKey = new BasicHeader("Authorization", "Bearer " + generateApiToken(TEST_TOKEN_PAYLOAD));
        authenticateWithApiToken(apiTokenOriginalKey, HttpStatus.SC_OK);

        // Change the signing key
        patchApiTokenConfig(defaultApiTokenConfig().signingKey(alternativeSigningKey));

        // Original key should no longer work
        authenticateWithApiToken(apiTokenOriginalKey, HttpStatus.SC_UNAUTHORIZED);

        // Generate new key, check that it is valid
        final Header apiTokenOtherKey = new BasicHeader("Authorization", "Bearer " + generateApiToken(TEST_TOKEN_PAYLOAD));
        authenticateWithApiToken(apiTokenOtherKey, HttpStatus.SC_OK);

        // Change back to the original signing key and the original key still works, and the new key doesn't
        patchApiTokenConfig(defaultApiTokenConfig());
        authenticateWithApiToken(apiTokenOriginalKey, HttpStatus.SC_OK);
        authenticateWithApiToken(apiTokenOtherKey, HttpStatus.SC_UNAUTHORIZED);
    }

    @Test
    public void testApiTokenWithIndexPermissions_canSearchAllowedIndex() {
        // Create the allowed index as admin
        try (TestRestClient adminClient = cluster.getRestClient(ADMIN_USER)) {
            adminClient.putJson("test-index-allowed", "{\"settings\":{\"number_of_shards\":1}}").assertStatusCode(HttpStatus.SC_OK);
        }

        String apiToken = generateApiToken(TEST_TOKEN_WITH_INDEX_PERMISSIONS_PAYLOAD);
        Header authHeader = new BasicHeader("Authorization", "Bearer " + apiToken);

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
    public void testExpiredApiToken_isRejected() {
        // Create a token with an expiration in the past (1 ms after epoch)
        String expiredPayload = """
            {
              "name": "expired-token",
              "cluster_permissions": ["cluster_monitor"],
              "expiration": 1
            }
            """;
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(CREATE_API_TOKEN_PATH, expiredPayload);
            response.assertStatusCode(HttpStatus.SC_OK);
            String expiredToken = response.getTextFromJsonBody("/token").toString();
            Header authHeader = new BasicHeader("Authorization", "Bearer " + expiredToken);
            authenticateWithApiToken(authHeader, HttpStatus.SC_UNAUTHORIZED);
        }
    }

    private String generateApiToken(String payload) {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(CREATE_API_TOKEN_PATH, payload);
            response.assertStatusCode(HttpStatus.SC_OK);
            return response.getTextFromJsonBody("/token").toString();
        }
    }

    private void authenticateWithApiToken(Header authHeader, int expectedStatusCode) {
        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.getAuthInfo();
            response.assertStatusCode(expectedStatusCode);
            assertThat(response.getStatusCode(), equalTo(expectedStatusCode));
            if (expectedStatusCode == HttpStatus.SC_OK) {
                String username = response.getTextFromJsonBody(POINTER_USERNAME);
                assertThat(username, equalTo(ApiTokenTest.TEST_TOKEN_SUBJECT));
            }
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
