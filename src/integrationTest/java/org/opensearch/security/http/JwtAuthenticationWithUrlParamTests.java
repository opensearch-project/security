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
import java.util.Base64;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.Header;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.AuditCompliance;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.JwtConfigBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.test.framework.log.LogsRule;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.apache.http.HttpHeaders.AUTHORIZATION;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.BASIC_AUTH_DOMAIN_ORDER;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.userAuthenticated;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class JwtAuthenticationWithUrlParamTests {

    public static final String CLAIM_USERNAME = "preferred-username";
    public static final String CLAIM_ROLES = "backend-user-roles";
    public static final String POINTER_USERNAME = "/user_name";

    private static final KeyPair KEY_PAIR = Keys.keyPairFor(SignatureAlgorithm.RS256);
    private static final String PUBLIC_KEY = new String(Base64.getEncoder().encode(KEY_PAIR.getPublic().getEncoded()), US_ASCII);

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    private static final String TOKEN_URL_PARAM = "token";

    private static final JwtAuthorizationHeaderFactory tokenFactory = new JwtAuthorizationHeaderFactory(
        KEY_PAIR.getPrivate(),
        CLAIM_USERNAME,
        CLAIM_ROLES,
        AUTHORIZATION
    );

    public static final TestSecurityConfig.AuthcDomain JWT_AUTH_DOMAIN = new TestSecurityConfig.AuthcDomain(
        "jwt",
        BASIC_AUTH_DOMAIN_ORDER - 1
    ).jwtHttpAuthenticator(
        new JwtConfigBuilder().jwtUrlParameter(TOKEN_URL_PARAM).signingKey(PUBLIC_KEY).subjectKey(CLAIM_USERNAME).rolesKey(CLAIM_ROLES)
    ).backend("noop");

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .nodeSettings(
            Map.of("plugins.security.restapi.roles_enabled", List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()))
        )
        .audit(
            new AuditConfiguration(true).compliance(new AuditCompliance().enabled(true))
                .filters(new AuditFilters().enabledRest(true).enabledTransport(true))
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .authc(JWT_AUTH_DOMAIN)
        .users(ADMIN_USER)
        .build();

    @Rule
    public LogsRule logsRule = new LogsRule("com.amazon.dlic.auth.http.jwt.HTTPJwtAuthenticator");

    @Test
    public void shouldAuthenticateWithJwtTokenInUrl_positive() {
        Header jwtToken = tokenFactory.generateValidToken(ADMIN_USER.getName());
        String jwtTokenValue = jwtToken.getValue();
        try (TestRestClient client = cluster.getRestClient()) {
            HttpResponse response = client.getAuthInfo(Map.of(TOKEN_URL_PARAM, jwtTokenValue, "verbose", "true"));

            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(ADMIN_USER.getName()));
            Map<String, String> expectedParams = Map.of("token", "REDACTED", "verbose", "true");

            auditLogsRule.assertExactlyOne(
                userAuthenticated(ADMIN_USER).withRestRequest(GET, "/_opendistro/_security/authinfo").withRestParams(expectedParams)
            );
        }
    }

    @Test
    public void testUnauthenticatedRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
            logsRule.assertThatContainExactly(String.format("No JWT token found in '%s' url parameter header", TOKEN_URL_PARAM));
        }
    }
}
