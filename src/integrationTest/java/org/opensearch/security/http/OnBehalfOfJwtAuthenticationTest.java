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
import org.apache.hc.core5.http.HttpStatus;
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
import static org.opensearch.security.support.ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
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
    public static final String OBO_USER_NAME_WITH_PERM = "obo_user";
    public static final String OBO_USER_NAME_NO_PERM = "obo_user_no_perm";
    public static final String DEFAULT_PASSWORD = "secret";
    public static final String NEW_PASSWORD = "testPassword123!!";
    public static final String OBO_TOKEN_REASON = "{\"reason\":\"Test generation\"}";
    public static final String OBO_ENDPOINT_PREFIX = "_plugins/_security/api/generateonbehalfoftoken";
    public static final String OBO_DESCRIPTION = "{\"description\":\"Testing\", \"service\":\"self-issued\"}";
    public static final String CURRENT_AND_NEW_PASSWORDS = "{ \"current_password\": \""
        + DEFAULT_PASSWORD
        + "\", \"password\": \""
        + NEW_PASSWORD
        + "\" }";

    protected final static TestSecurityConfig.User OBO_USER = new TestSecurityConfig.User(OBO_USER_NAME_WITH_PERM).roles(
        new TestSecurityConfig.Role("obo_access_role").clusterPermissions("security:obo/create")
    );

    protected final static TestSecurityConfig.User OBO_USER_NO_PERM = new TestSecurityConfig.User(OBO_USER_NAME_NO_PERM).roles(
        new TestSecurityConfig.Role("obo_user_no_perm")
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .users(ADMIN_USER, OBO_USER, OBO_USER_NO_PERM)
        .nodeSettings(
            Map.of(SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true, SECURITY_RESTAPI_ROLES_ENABLED, List.of("user_admin__all_access"))
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .onBehalfOf(new OnBehalfOfConfig().oboEnabled(oboEnabled).signingKey(signingKey).encryptionKey(encryptionKey))
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
            TestRestClient.HttpResponse response = client.getOnBehalfOfToken(OBO_DESCRIPTION, adminOboAuthHeader);
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

    @Test
    public void shouldAuthenticateForNonAdminUserWithOBOPermission() {
        String oboToken = generateOboToken(OBO_USER_NAME_WITH_PERM, DEFAULT_PASSWORD);
        Header oboAuthHeader = new BasicHeader("Authorization", "Bearer " + oboToken);
        authenticateWithOboToken(oboAuthHeader, OBO_USER_NAME_WITH_PERM, 200);
    }

    @Test
    public void shouldNotAuthenticateForNonAdminUserWithoutOBOPermission() {
        try (TestRestClient client = cluster.getRestClient(OBO_USER_NO_PERM)) {
            assertThat(client.post(OBO_ENDPOINT_PREFIX).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
        }
    }

    private String generateOboToken(String username, String password) {
        try (TestRestClient client = cluster.getRestClient(username, password)) {
            client.assertCorrectCredentials(username);
            TestRestClient.HttpResponse response = client.postJson(OBO_ENDPOINT_PREFIX, OBO_TOKEN_REASON);
            response.assertStatusCode(200);
            Map<String, Object> oboEndPointResponse = response.getBodyAs(Map.class);
            assertThat(
                oboEndPointResponse,
                allOf(aMapWithSize(3), hasKey("user"), hasKey("authenticationToken"), hasKey("durationSeconds"))
            );
            return oboEndPointResponse.get("authenticationToken").toString();
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
