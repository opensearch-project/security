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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.authtoken.jwt.EncryptionDecryptionUtil;
import org.opensearch.test.framework.OnBehalfOfConfig;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.opensearch.security.support.ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class OnBehalfOfJwtAuthenticationTest {

    public static final String POINTER_USERNAME = "/user_name";

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    private static final String CREATE_OBO_TOKEN_PATH = "_plugins/_security/api/generateonbehalfoftoken";
    private static Boolean oboEnabled = true;
    private static final String signingKey = Base64.getEncoder()
        .encodeToString(
            "jwt signing key for an on behalf of token authentication backend for testing of OBO authentication".getBytes(
                StandardCharsets.UTF_8
            )
        );
    private static final String alternativeSigningKey = Base64.getEncoder()
        .encodeToString(
            "alternativeSigningKeyalternativeSigningKeyalternativeSigningKeyalternativeSigningKey".getBytes(StandardCharsets.UTF_8)
        );

    private static final String encryptionKey = Base64.getEncoder().encodeToString("encryptionKey".getBytes(StandardCharsets.UTF_8));
    public static final String ADMIN_USER_NAME = "admin";
    public static final String OBO_USER_NAME_WITH_PERM = "obo_user";
    public static final String OBO_USER_NAME_NO_PERM = "obo_user_no_perm";
    public static final String DEFAULT_PASSWORD = "secret";
    public static final String NEW_PASSWORD = "testPassword123!!";
    public static final String OBO_TOKEN_REASON = "{\"description\":\"Test generation\"}";
    public static final String OBO_ENDPOINT_PREFIX = "_plugins/_security/api/generateonbehalfoftoken";
    public static final String OBO_DESCRIPTION = "{\"description\":\"Testing\", \"service\":\"self-issued\"}";

    public static final String OBO_DESCRIPTION_WITH_INVALID_DURATIONSECONDS =
        "{\"description\":\"Testing\", \"service\":\"self-issued\", \"durationSeconds\":\"invalid-seconds\"}";

    public static final String OBO_DESCRIPTION_WITH_INVALID_PARAMETERS =
        "{\"description\":\"Testing\", \"service\":\"self-issued\", \"invalidParameter\":\"invalid-parameter\"}";

    public static final String HOST_MAPPING_IP = "127.0.0.1";
    public static final String OBO_USER_NAME_WITH_HOST_MAPPING = "obo_user_with_ip_role_mapping";
    public static final String CURRENT_AND_NEW_PASSWORDS = "{ \"current_password\": \""
        + DEFAULT_PASSWORD
        + "\", \"password\": \""
        + NEW_PASSWORD
        + "\" }";

    private static final TestSecurityConfig.Role ROLE_WITH_OBO_PERM = new TestSecurityConfig.Role("obo_access_role").clusterPermissions(
        "security:obo/create"
    );

    private static final TestSecurityConfig.Role ROLE_WITH_NO_OBO_PERM = new TestSecurityConfig.Role("obo_user_no_perm");

    protected final static TestSecurityConfig.User OBO_USER = new TestSecurityConfig.User(OBO_USER_NAME_WITH_PERM).roles(
        ROLE_WITH_OBO_PERM
    );

    protected final static TestSecurityConfig.User OBO_USER_NO_PERM = new TestSecurityConfig.User(OBO_USER_NAME_NO_PERM).roles(
        ROLE_WITH_NO_OBO_PERM
    );

    private static final TestSecurityConfig.Role HOST_MAPPING_ROLE = new TestSecurityConfig.Role("host_mapping_role");

    protected final static TestSecurityConfig.User HOST_MAPPING_OBO_USER = new TestSecurityConfig.User(OBO_USER_NAME_WITH_HOST_MAPPING)
        .roles(HOST_MAPPING_ROLE, ROLE_WITH_OBO_PERM);

    private static OnBehalfOfConfig defaultOnBehalfOfConfig() {
        return new OnBehalfOfConfig().oboEnabled(oboEnabled).signingKey(signingKey).encryptionKey(encryptionKey);
    }

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .users(ADMIN_USER, OBO_USER, OBO_USER_NO_PERM, HOST_MAPPING_OBO_USER)
        .nodeSettings(
            Map.of(
                SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST,
                false,
                SECURITY_RESTAPI_ROLES_ENABLED,
                ADMIN_USER.getRoleNames(),
                SECURITY_RESTAPI_ADMIN_ENABLED,
                true,
                "plugins.security.unsupported.restapi.allow_securityconfig_modification",
                true
            )
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .rolesMapping(new TestSecurityConfig.RoleMapping(HOST_MAPPING_ROLE.getName()).hosts(HOST_MAPPING_IP))
        .onBehalfOf(defaultOnBehalfOfConfig())
        .build();

    @Before
    public void before() {
        patchOnBehalfOfConfig(defaultOnBehalfOfConfig());
    }

    @Test
    public void shouldAuthenticateWithOBOTokenEndPoint() {
        String oboToken = generateOboToken(ADMIN_USER_NAME, DEFAULT_PASSWORD);
        Header adminOboAuthHeader = new BasicHeader("Authorization", "Bearer " + oboToken);
        authenticateWithOboToken(adminOboAuthHeader, ADMIN_USER_NAME, HttpStatus.SC_OK);
    }

    @Test
    public void shouldNotAuthenticateWithATemperedOBOToken() {
        String oboToken = generateOboToken(ADMIN_USER_NAME, DEFAULT_PASSWORD);
        oboToken = oboToken.substring(0, oboToken.length() - 1); // tampering the token
        Header adminOboAuthHeader = new BasicHeader("Authorization", "Bearer " + oboToken);
        authenticateWithOboToken(adminOboAuthHeader, ADMIN_USER_NAME, HttpStatus.SC_UNAUTHORIZED);
    }

    @Test
    public void shouldNotAuthenticateForUsingOBOTokenToAccessOBOEndpoint() {
        String oboToken = generateOboToken(ADMIN_USER_NAME, DEFAULT_PASSWORD);
        Header adminOboAuthHeader = new BasicHeader("Authorization", "Bearer " + oboToken);

        try (TestRestClient client = cluster.getRestClient(adminOboAuthHeader)) {
            TestRestClient.HttpResponse response = client.postJson(CREATE_OBO_TOKEN_PATH, OBO_DESCRIPTION);
            response.assertStatusCode(HttpStatus.SC_UNAUTHORIZED);
        }
    }

    @Test
    public void shouldNotAuthenticateForUsingOBOTokenToAccessAccountEndpoint() {
        String oboToken = generateOboToken(ADMIN_USER_NAME, DEFAULT_PASSWORD);
        Header adminOboAuthHeader = new BasicHeader("Authorization", "Bearer " + oboToken);

        try (TestRestClient client = cluster.getRestClient(adminOboAuthHeader)) {
            TestRestClient.HttpResponse response = client.putJson("_plugins/_security/api/account", CURRENT_AND_NEW_PASSWORDS);
            response.assertStatusCode(HttpStatus.SC_UNAUTHORIZED);
        }
    }

    @Test
    public void shouldAuthenticateForNonAdminUserWithOBOPermission() {
        String oboToken = generateOboToken(OBO_USER_NAME_WITH_PERM, DEFAULT_PASSWORD);
        Header oboAuthHeader = new BasicHeader("Authorization", "Bearer " + oboToken);
        authenticateWithOboToken(oboAuthHeader, OBO_USER_NAME_WITH_PERM, HttpStatus.SC_OK);
    }

    @Test
    public void shouldNotAuthenticateForNonAdminUserWithoutOBOPermission() {
        try (TestRestClient client = cluster.getRestClient(OBO_USER_NO_PERM)) {
            assertThat(client.post(OBO_ENDPOINT_PREFIX).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
        }
    }

    @Test
    public void shouldNotIncludeRolesFromHostMappingInOBOToken() {
        String oboToken = generateOboToken(OBO_USER_NAME_WITH_HOST_MAPPING, DEFAULT_PASSWORD);

        Claims claims = Jwts.parser().setSigningKey(Base64.getDecoder().decode(signingKey)).build().parseClaimsJws(oboToken).getBody();

        Object er = claims.get("er");
        EncryptionDecryptionUtil encryptionDecryptionUtil = new EncryptionDecryptionUtil(encryptionKey);
        String rolesClaim = encryptionDecryptionUtil.decrypt(er.toString());
        Set<String> roles = Arrays.stream(rolesClaim.split(",")).map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toSet());

        assertThat(roles, equalTo(HOST_MAPPING_OBO_USER.getRoleNames()));
        assertThat(roles, not(contains("host_mapping_role")));
    }

    @Test
    public void shouldNotAuthenticateWithInvalidDurationSeconds() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER_NAME, DEFAULT_PASSWORD)) {
            client.confirmCorrectCredentials(ADMIN_USER_NAME);
            TestRestClient.HttpResponse response = client.postJson(OBO_ENDPOINT_PREFIX, OBO_DESCRIPTION_WITH_INVALID_DURATIONSECONDS);
            response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(response.getTextFromJsonBody("/error"), equalTo("durationSeconds must be a number."));
        }
    }

    @Test
    public void shouldNotAuthenticateWithInvalidAPIParameter() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER_NAME, DEFAULT_PASSWORD)) {
            client.confirmCorrectCredentials(ADMIN_USER_NAME);
            TestRestClient.HttpResponse response = client.postJson(OBO_ENDPOINT_PREFIX, OBO_DESCRIPTION_WITH_INVALID_PARAMETERS);
            response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(response.getTextFromJsonBody("/error"), equalTo("Unrecognized parameter: invalidParameter"));
        }
    }

    @Test
    public void shouldNotAllowTokenWhenOboIsDisabled() {
        final String oboToken = generateOboToken(OBO_USER_NAME_WITH_PERM, DEFAULT_PASSWORD);
        final Header oboHeader = new BasicHeader("Authorization", "Bearer " + oboToken);
        authenticateWithOboToken(oboHeader, OBO_USER_NAME_WITH_PERM, HttpStatus.SC_OK);

        // Disable OBO via config and see that the authenticator doesn't authorize
        patchOnBehalfOfConfig(defaultOnBehalfOfConfig().oboEnabled(false));
        authenticateWithOboToken(oboHeader, OBO_USER_NAME_WITH_PERM, HttpStatus.SC_UNAUTHORIZED);

        // Reenable OBO via config and see that the authenticator is working again
        patchOnBehalfOfConfig(defaultOnBehalfOfConfig().oboEnabled(true));
        authenticateWithOboToken(oboHeader, OBO_USER_NAME_WITH_PERM, HttpStatus.SC_OK);
    }

    @Test
    public void oboSigningCheckChangeIsDetected() {
        final String oboTokenOrignalKey = generateOboToken(OBO_USER_NAME_WITH_PERM, DEFAULT_PASSWORD);
        final Header oboHeaderOriginalKey = new BasicHeader("Authorization", "Bearer " + oboTokenOrignalKey);
        authenticateWithOboToken(oboHeaderOriginalKey, OBO_USER_NAME_WITH_PERM, HttpStatus.SC_OK);

        // Change the signing key
        patchOnBehalfOfConfig(defaultOnBehalfOfConfig().signingKey(alternativeSigningKey));

        // Original key should no longer work
        authenticateWithOboToken(oboHeaderOriginalKey, OBO_USER_NAME_WITH_PERM, HttpStatus.SC_UNAUTHORIZED);

        // Generate new key, check that it is valid
        final String oboTokenOtherKey = generateOboToken(OBO_USER_NAME_WITH_PERM, DEFAULT_PASSWORD);
        final Header oboHeaderOtherKey = new BasicHeader("Authorization", "Bearer " + oboTokenOtherKey);
        authenticateWithOboToken(oboHeaderOtherKey, OBO_USER_NAME_WITH_PERM, HttpStatus.SC_OK);

        // Change back to the original signing key and the original key still works, and the new key doesn't
        patchOnBehalfOfConfig(defaultOnBehalfOfConfig());
        authenticateWithOboToken(oboHeaderOriginalKey, OBO_USER_NAME_WITH_PERM, HttpStatus.SC_OK);
        authenticateWithOboToken(oboHeaderOtherKey, OBO_USER_NAME_WITH_PERM, HttpStatus.SC_UNAUTHORIZED);
    }

    private String generateOboToken(String username, String password) {
        try (TestRestClient client = cluster.getRestClient(username, password)) {
            client.confirmCorrectCredentials(username);
            TestRestClient.HttpResponse response = client.postJson(OBO_ENDPOINT_PREFIX, OBO_TOKEN_REASON);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getTextFromJsonBody("/user"), notNullValue());
            assertThat(response.getTextFromJsonBody("/authenticationToken"), notNullValue());
            assertThat(response.getTextFromJsonBody("/durationSeconds"), notNullValue());
            return response.getTextFromJsonBody("/authenticationToken").toString();
        }
    }

    private void authenticateWithOboToken(Header authHeader, String expectedUsername, int expectedStatusCode) {
        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.getAuthInfo();
            response.assertStatusCode(expectedStatusCode);
            assertThat(response.getStatusCode(), equalTo(expectedStatusCode));
            if (expectedStatusCode == HttpStatus.SC_OK) {
                String username = response.getTextFromJsonBody(POINTER_USERNAME);
                assertThat(username, equalTo(expectedUsername));
            }
        }
    }

    private void patchOnBehalfOfConfig(final OnBehalfOfConfig oboConfig) {
        try (final TestRestClient adminClient = cluster.getRestClient(cluster.getAdminCertificate())) {
            final XContentBuilder configBuilder = XContentFactory.jsonBuilder();
            configBuilder.value(oboConfig);

            final String patchBody = "[{ \"op\": \"replace\", \"path\": \"/config/dynamic/on_behalf_of\", \"value\":"
                + configBuilder.toString()
                + "}]";
            final var response = adminClient.patch("_plugins/_security/api/securityconfig", patchBody);
            response.assertStatusCode(HttpStatus.SC_OK);
        } catch (final IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
