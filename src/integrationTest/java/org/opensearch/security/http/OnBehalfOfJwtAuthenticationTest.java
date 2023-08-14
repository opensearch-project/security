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

package org.opensearch.security.http;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.OnBehalfOfConfig;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class OnBehalfOfJwtAuthenticationTest {

    public static final String POINTER_USERNAME = "/user_name";

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    private static Boolean oboEnabled = true;
    private static final String signingKey = Base64.getEncoder()
        .encodeToString(
            "jwt signing key for an on behalf of token authentication backend for testing of OBO authentication".getBytes(
                StandardCharsets.UTF_8
            )
        );
    private static final String encryptionKey = Base64.getEncoder().encodeToString("encryptionKey".getBytes(StandardCharsets.UTF_8));
    public static final String ADMIN_USER_NAME = "admin";
    public static final String DEFAULT_PASSWORD = "secret";
    public static final String NEW_PASSWORD = "testPassword123!!";
    public static final String OBO_TOKEN_REASON = "{\"reason\":\"Test generation\"}";
    public static final String OBO_ENDPOINT_PREFIX = "_plugins/_security/api/user/onbehalfof";
    public static final String OBO_REASON = "{\"reason\":\"Testing\", \"service\":\"self-issued\"}";
    public static final String CURRENT_AND_NEW_PASSWORDS = "{ \"current_password\": \""
        + DEFAULT_PASSWORD
        + "\", \"password\": \""
        + NEW_PASSWORD
        + "\" }";

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .users(ADMIN_USER)
        .nodeSettings(
            Map.of(
                "plugins.security.allow_default_init_securityindex",
                true,
                "plugins.security.restapi.roles_enabled",
                List.of("user_admin__all_access")
            )
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .onBehalfOf(new OnBehalfOfConfig().oboEnabled(oboEnabled).signing_key(signingKey).encryption_key(encryptionKey))
        .build();

    @Test
    public void shouldAuthenticateWithOBOTokenEndPoint() {
        String oboToken = generateOboToken(ADMIN_USER_NAME, DEFAULT_PASSWORD);
        Header adminOboAuthHeader = new BasicHeader("Authorization", "Bearer " + oboToken);
        authenticateWithOboToken(adminOboAuthHeader, ADMIN_USER_NAME, 200);
    }

    @Test
    public void shouldNotAuthenticateWithATemperedOBOToken() {
        String oboToken = generateOboToken(ADMIN_USER_NAME, DEFAULT_PASSWORD);
        oboToken = oboToken.substring(0, oboToken.length() - 1); // tampering the token
        Header adminOboAuthHeader = new BasicHeader("Authorization", "Bearer " + oboToken);
        authenticateWithOboToken(adminOboAuthHeader, ADMIN_USER_NAME, 401);
    }

    @Test
    public void shouldNotAuthenticateForUsingOBOTokenToAccessOBOEndpoint() {
        String oboToken = generateOboToken(ADMIN_USER_NAME, DEFAULT_PASSWORD);
        Header adminOboAuthHeader = new BasicHeader("Authorization", "Bearer " + oboToken);

        try (TestRestClient client = cluster.getRestClient(adminOboAuthHeader)) {
            TestRestClient.HttpResponse response = client.getOBOTokenFromOboEndpoint(OBO_REASON, adminOboAuthHeader);
            response.assertStatusCode(401);
        }
    }

    @Test
    public void shouldNotAuthenticateForUsingOBOTokenToAccessAccountEndpoint() {
        String oboToken = generateOboToken(ADMIN_USER_NAME, DEFAULT_PASSWORD);
        Header adminOboAuthHeader = new BasicHeader("Authorization", "Bearer " + oboToken);

        try (TestRestClient client = cluster.getRestClient(adminOboAuthHeader)) {
            TestRestClient.HttpResponse response = client.changeInternalUserPassword(CURRENT_AND_NEW_PASSWORDS, adminOboAuthHeader);
            response.assertStatusCode(401);
        }
    }

    private String generateOboToken(String username, String password) {
        try (TestRestClient client = cluster.getRestClient(username, password)) {
            client.assertCorrectCredentials(username);
            TestRestClient.HttpResponse response = client.postJson(OBO_ENDPOINT_PREFIX, OBO_TOKEN_REASON);
            response.assertStatusCode(200);
            Map<String, Object> oboEndPointResponse = response.getBodyAs(Map.class);
            assertThat(oboEndPointResponse, allOf(aMapWithSize(3), hasKey("user"), hasKey("onBehalfOfToken"), hasKey("duration")));
            return oboEndPointResponse.get("onBehalfOfToken").toString();
        }
    }

    private void authenticateWithOboToken(Header authHeader, String expectedUsername, int expectedStatusCode) {
        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.getAuthInfo();
            response.assertStatusCode(expectedStatusCode);
            if (expectedStatusCode == 200) {
                String username = response.getTextFromJsonBody(POINTER_USERNAME);
                assertThat(username, equalTo(expectedUsername));
            } else {
                Assert.assertTrue(response.getBody().contains("Unauthorized"));
            }
        }
    }
}
