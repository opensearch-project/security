/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security.http;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.hc.core5.http.Header;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.JwtConfigBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.test.framework.log.LogsRule;
import org.opensearch.transport.client.Client;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.security.http.JwtAuthenticationTests.POINTER_BACKEND_ROLES;
import static org.opensearch.security.http.JwtAuthenticationTests.POINTER_USERNAME;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.BASIC_AUTH_DOMAIN_ORDER;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class JwtAuthenticationNestedClaimsTests {

    public static final String CLAIM_USERNAME = "preferred-username";
    public static final List<String> CLAIM_ROLES = List.of("attributes", "roles");

    public static final String USER_SUPERHERO = "superhero";
    public static final String ROLE_VP = "role_vp";

    public static final String QA_DEPARTMENT = "qa-department";

    public static final String CLAIM_DEPARTMENT = "department";

    public static final String DEPARTMENT_SONG_INDEX_PATTERN = String.format("song_lyrics_${attr.jwt.%s}", CLAIM_DEPARTMENT);

    public static final String QA_SONG_INDEX_NAME = String.format("song_lyrics_%s", QA_DEPARTMENT);

    private static final KeyPair KEY_PAIR1 = Keys.keyPairFor(SignatureAlgorithm.RS256);
    private static final String PUBLIC_KEY1 = new String(Base64.getEncoder().encode(KEY_PAIR1.getPublic().getEncoded()), US_ASCII);

    private static final KeyPair KEY_PAIR2 = Keys.keyPairFor(SignatureAlgorithm.RS256);
    private static final String PUBLIC_KEY2 = new String(Base64.getEncoder().encode(KEY_PAIR2.getPublic().getEncoded()), US_ASCII);

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    private static final String JWT_AUTH_HEADER = "jwt-auth";

    private static final JwtAuthorizationHeaderFactory tokenFactory1 = new JwtAuthorizationHeaderFactory(
        KEY_PAIR1.getPrivate(),
        CLAIM_USERNAME,
        CLAIM_ROLES,
        JWT_AUTH_HEADER
    );
    public static final TestSecurityConfig.AuthcDomain JWT_AUTH_DOMAIN = new TestSecurityConfig.AuthcDomain(
        "jwt",
        BASIC_AUTH_DOMAIN_ORDER - 1
    ).jwtHttpAuthenticator(
        new JwtConfigBuilder().jwtHeader(JWT_AUTH_HEADER)
            .signingKey(List.of(PUBLIC_KEY1, PUBLIC_KEY2))
            .subjectKey(CLAIM_USERNAME)
            .rolesKey(CLAIM_ROLES)
    ).backend("noop");
    public static final String SONG_ID_1 = "song-id-01";

    public static final Role DEPARTMENT_SONG_LISTENER_ROLE = new Role("department-song-listener-role").indexPermissions(
        "indices:data/read/search"
    ).on(DEPARTMENT_SONG_INDEX_PATTERN);

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .nodeSettings(
            Map.of("plugins.security.restapi.roles_enabled", List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()))
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
        .roles(DEPARTMENT_SONG_LISTENER_ROLE)
        .authc(JWT_AUTH_DOMAIN)
        .build();

    @Rule
    public LogsRule logsRule = new LogsRule("org.opensearch.security.auth.http.jwt.HTTPJwtAuthenticator");

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.prepareIndex(QA_SONG_INDEX_NAME).setId(SONG_ID_1).setRefreshPolicy(IMMEDIATE).setSource(SONGS[0].asMap()).get();
        }
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.createRoleMapping(ROLE_VP, DEPARTMENT_SONG_LISTENER_ROLE.getName());
        }
    }

    // TODO write tests for scenarios where roles are in nested claim. i.e. rolesKey: ['attributes', 'roles']
    @Test
    public void shouldAuthenticateWithNestedRolesClaim() {
        // Create nested claims structure
        Map<String, Object> attributes = new HashMap<>();
        List<String> rolesClaim = Arrays.asList("all_access", "securitymanager");
        attributes.put("roles", rolesClaim);

        Map<String, Object> nestedClaims = new HashMap<>();
        nestedClaims.put("attributes", attributes);

        // Generate token with nested claims
        Header header = tokenFactory1.generateValidTokenWithCustomClaims(USER_SUPERHERO, null, nestedClaims);

        try (TestRestClient client = cluster.getRestClient(header)) {
            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_SUPERHERO));
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(roles, hasSize(2));
            assertThat(roles, containsInAnyOrder("all_access", "securitymanager"));
        }
    }

    @Test
    public void shouldHandleMissingNestedRolesClaim() {
        // Create invalid nested claims structure
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("wrong", "missing"); // Invalid format - should be a list

        Map<String, Object> nestedClaims = new HashMap<>();
        nestedClaims.put("attributes", attributes);

        Header header = tokenFactory1.generateValidTokenWithCustomClaims(USER_SUPERHERO, null, nestedClaims);

        try (TestRestClient client = cluster.getRestClient(header)) {
            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_SUPERHERO));
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(roles, hasSize(0));
        }
    }
}
