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

import java.io.IOException;
import java.security.KeyPair;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.JwtConfigBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.OpenSearchClientProvider.CloseableOpenSearchClient;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.test.framework.log.LogsRule;
import org.opensearch.transport.client.Client;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.apache.http.HttpHeaders.AUTHORIZATION;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.core.rest.RestStatus.FORBIDDEN;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.security.Song.FIELD_TITLE;
import static org.opensearch.security.Song.QUERY_TITLE_MAGNUM_OPUS;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.security.Song.TITLE_MAGNUM_OPUS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.BASIC_AUTH_DOMAIN_ORDER;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.client.SearchRequestFactory.queryStringQueryRequest;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.numberOfTotalHitsIsEqualTo;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.searchHitContainsFieldWithValue;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.searchHitsContainDocumentWithId;
import static org.opensearch.test.framework.matcher.client.TransportExceptionMatchers.statusException;

public class JwtAuthenticationTests {

    public static final List<String> CLAIM_USERNAME = List.of("preferred-username");
    public static final List<String> CLAIM_ROLES = List.of("backend-user-roles");

    public static final String USER_SUPERHERO = "superhero";
    public static final String USERNAME_ROOT = "root";
    public static final String ROLE_ADMIN = "role_admin";
    public static final String ROLE_DEVELOPER = "role_developer";
    public static final String ROLE_QA = "role_qa";
    public static final String ROLE_CTO = "role_cto";
    public static final String ROLE_CEO = "role_ceo";
    public static final String ROLE_VP = "role_vp";
    public static final String POINTER_BACKEND_ROLES = "/backend_roles";
    public static final String POINTER_USERNAME = "/user_name";

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

    private static final JwtAuthorizationHeaderFactory tokenFactory2 = new JwtAuthorizationHeaderFactory(
        KEY_PAIR2.getPrivate(),
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
        .audit(new AuditConfiguration(true).filters(new AuditFilters().enabledRest(true).enabledTransport(true)))
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
        .roles(DEPARTMENT_SONG_LISTENER_ROLE)
        .authc(JWT_AUTH_DOMAIN)
        .build();

    @Rule
    public LogsRule logsRule = new LogsRule("org.opensearch.security.auth.http.jwt.HTTPJwtAuthenticator");

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.prepareIndex(QA_SONG_INDEX_NAME).setId(SONG_ID_1).setRefreshPolicy(IMMEDIATE).setSource(SONGS[0].asMap()).get();
        }
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.createRoleMapping(ROLE_VP, DEPARTMENT_SONG_LISTENER_ROLE.getName());
        }
    }

    @Test
    public void shouldAuthenticateWithJwtToken_positive() {
        try (TestRestClient client = cluster.getRestClient(tokenFactory1.generateValidToken(USER_SUPERHERO))) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_SUPERHERO));
        }
    }

    @Test
    public void shouldAuthenticateWithJwtToken_positiveWithAnotherUsername() {
        try (TestRestClient client = cluster.getRestClient(tokenFactory1.generateValidToken(USERNAME_ROOT))) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USERNAME_ROOT));
        }
    }

    @Test
    public void shouldAuthenticateWithJwtToken_failureLackingUserName() {
        try (TestRestClient client = cluster.getRestClient(tokenFactory1.generateTokenWithoutPreferredUsername(USER_SUPERHERO))) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
            logsRule.assertThatContainExactly("No subject found in JWT token");
        }
    }

    @Test
    public void shouldAuthenticateWithJwtToken_failureExpiredToken() {
        try (TestRestClient client = cluster.getRestClient(tokenFactory1.generateExpiredToken(USER_SUPERHERO))) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
            logsRule.assertThatContainExactly("Invalid or expired JWT token.");
        }
    }

    @Test
    public void shouldAuthenticateWithJwtToken_failureIncorrectFormatOfToken() {
        Header header = new BasicHeader(AUTHORIZATION, "not.a.token");
        try (TestRestClient client = cluster.getRestClient(header)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
            logsRule.assertThatContainExactly(String.format("No JWT token found in '%s' header header", JWT_AUTH_HEADER));
        }
    }

    @Test
    public void shouldAuthenticateWithJwtToken_failureIncorrectSignature() {
        KeyPair incorrectKeyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        Header header = tokenFactory1.generateTokenSignedWithKey(incorrectKeyPair.getPrivate(), USER_SUPERHERO);
        try (TestRestClient client = cluster.getRestClient(header)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
            logsRule.assertThatContainExactly("Invalid or expired JWT token.");
        }
    }

    @Test
    public void shouldRejectReservedJwtSubjectAndAuditFailedLogin() {
        Header header = tokenFactory1.generateValidToken("plugin:reserved-subject");
        try (TestRestClient client = cluster.getRestClient(header)) {
            client.getAuthInfo().assertStatusCode(401);
        }

        logsRule.assertThatContainExactly("JWT subject uses a reserved security prefix");
        auditLogsRule.assertExactlyOne((AuditMessage message) -> {
            Map<String, Object> fields = message.getAsMap();
            return message.getCategory() == AuditCategory.FAILED_LOGIN
                && "<NONE>".equals(String.valueOf(fields.get(AuditMessage.REQUEST_EFFECTIVE_USER)))
                && "REST".equals(String.valueOf(fields.get(AuditMessage.ORIGIN)))
                && "REST".equals(String.valueOf(fields.get(AuditMessage.REQUEST_LAYER)))
                && GET.name().equals(String.valueOf(fields.get(AuditMessage.REST_REQUEST_METHOD)))
                && "/_opendistro/_security/authinfo".equals(String.valueOf(fields.get(AuditMessage.REST_REQUEST_PATH)))
                && Boolean.FALSE.equals(fields.get(AuditMessage.IS_ADMIN_DN))
                && !fields.containsKey(AuditMessage.REQUEST_INITIATING_USER)
                && !fields.containsKey(AuditMessage.USER_ROLES)
                && !fields.containsKey(AuditMessage.AUTH_METHOD);
        });
    }

    @Test
    public void shouldReadRolesFromToken_positiveFirstRoleSet() {
        Header header = tokenFactory1.generateValidToken(USER_SUPERHERO, ROLE_ADMIN, ROLE_DEVELOPER, ROLE_QA);
        try (TestRestClient client = cluster.getRestClient(header)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(roles, hasSize(3));
            assertThat(roles, containsInAnyOrder(ROLE_ADMIN, ROLE_DEVELOPER, ROLE_QA));
        }
    }

    @Test
    public void shouldReadRolesFromToken_positiveSecondRoleSet() {
        Header header = tokenFactory1.generateValidToken(USER_SUPERHERO, ROLE_CTO, ROLE_CEO, ROLE_VP);
        try (TestRestClient client = cluster.getRestClient(header)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(roles, hasSize(3));
            assertThat(roles, containsInAnyOrder(ROLE_CTO, ROLE_CEO, ROLE_VP));
        }
    }

    @Test
    public void shouldExposeTokenClaimsAsUserAttributes_positive() throws IOException {
        String[] roles = { ROLE_VP };
        Map<String, Object> additionalClaims = Map.of(CLAIM_DEPARTMENT, QA_DEPARTMENT);
        Header header = tokenFactory1.generateValidTokenWithCustomClaims(USER_SUPERHERO, roles, additionalClaims);
        try (CloseableOpenSearchClient client = cluster.getClient(List.of(header))) {
            SearchRequest searchRequest = queryStringQueryRequest(QA_SONG_INDEX_NAME, QUERY_TITLE_MAGNUM_OPUS);

            SearchResponse<?> response = client.search(searchRequest, Map.class);

            assertThat(response, isSuccessfulSearchResponse());
            assertThat(response, numberOfTotalHitsIsEqualTo(1));
            assertThat(response, searchHitsContainDocumentWithId(0, QA_SONG_INDEX_NAME, SONG_ID_1));
            assertThat(response, searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_MAGNUM_OPUS));
        }
    }

    @Test
    public void shouldExposeTokenClaimsAsUserAttributes_negative() throws IOException {
        String[] roles = { ROLE_VP };
        Map<String, Object> additionalClaims = Map.of(CLAIM_DEPARTMENT, "department-without-access-to-qa-song-index");
        Header header = tokenFactory1.generateValidTokenWithCustomClaims(USER_SUPERHERO, roles, additionalClaims);
        try (CloseableOpenSearchClient client = cluster.getClient(List.of(header))) {
            SearchRequest searchRequest = queryStringQueryRequest(QA_SONG_INDEX_NAME, QUERY_TITLE_MAGNUM_OPUS);

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
    }

    @Test
    public void secondKeypairShouldAuthenticateWithJwtToken_positive() {
        try (TestRestClient client = cluster.getRestClient(tokenFactory2.generateValidToken(USER_SUPERHERO))) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_SUPERHERO));
        }
    }

    @Test
    public void secondKeypairShouldAuthenticateWithJwtToken_positiveWithAnotherUsername() {
        try (TestRestClient client = cluster.getRestClient(tokenFactory2.generateValidToken(USERNAME_ROOT))) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USERNAME_ROOT));
        }
    }
}
