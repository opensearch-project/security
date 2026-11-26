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
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.apache.http.HttpHeaders.AUTHORIZATION;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.BASIC_AUTH_DOMAIN_ORDER;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
 * Sets the required_claims setting through the security configuration, the same way an administrator would, so that parsing
 * of the setting and its validation are exercised end to end.
 */
public class JwtRequiredClaimsTests {

    private static final String JWT_USER = "jwt-user";
    private static final String POINTER_USERNAME = "/user_name";

    private static final KeyPair KEY_PAIR = Keys.keyPairFor(SignatureAlgorithm.RS256);
    private static final String PUBLIC_KEY = new String(Base64.getEncoder().encode(KEY_PAIR.getPublic().getEncoded()), US_ASCII);

    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    /** required_claims is a list: tokens must contain exp and nbf. */
    @ClassRule
    public static final LocalCluster LIST_CLUSTER = clusterWithRequiredClaims(List.of("exp", "nbf"));

    /** required_claims is a map, which is not a valid format. */
    @ClassRule
    public static final LocalCluster MAP_CLUSTER = clusterWithRequiredClaims(Map.of("exp", false));

    /** required_claims is a list with an empty entry, which is not valid. */
    @ClassRule
    public static final LocalCluster BLANK_ENTRY_CLUSTER = clusterWithRequiredClaims(List.of("exp", "", "nbf"));

    private static LocalCluster clusterWithRequiredClaims(Object requiredClaims) {
        Map<String, Object> config = Map.of("signing_key", List.of(PUBLIC_KEY), "required_claims", requiredClaims);
        TestSecurityConfig.AuthcDomain jwtDomain = new TestSecurityConfig.AuthcDomain("jwt", BASIC_AUTH_DOMAIN_ORDER - 1).httpAuthenticator(
            new TestSecurityConfig.AuthcDomain.HttpAuthenticator("jwt").challenge(false).config(config)
        ).backend("noop");
        return new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
            .anonymousAuth(false)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .authc(jwtDomain)
            .users(ADMIN_USER)
            .build();
    }

    private static Header bearer(JwtBuilder token) {
        return new BasicHeader(AUTHORIZATION, "Bearer " + token.signWith(KEY_PAIR.getPrivate(), SignatureAlgorithm.RS256).compact());
    }

    private static JwtBuilder tokenWithExpAndNbf() {
        long now = System.currentTimeMillis();
        return Jwts.builder().setSubject(JWT_USER).setNotBefore(new Date(now - 1_000)).setExpiration(new Date(now + 3_600_000));
    }

    @Test
    public void tokenWithAllRequiredClaimsIsAccepted() {
        try (TestRestClient client = LIST_CLUSTER.getRestClient(bearer(tokenWithExpAndNbf()))) {
            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            assertThat(response.getTextFromJsonBody(POINTER_USERNAME), equalTo(JWT_USER));
        }
    }

    @Test
    public void tokenWithoutExpIsRejected() {
        JwtBuilder token = Jwts.builder().setSubject(JWT_USER).setNotBefore(new Date(System.currentTimeMillis() - 1_000));

        try (TestRestClient client = LIST_CLUSTER.getRestClient(bearer(token))) {
            client.getAuthInfo().assertStatusCode(401);
        }
    }

    @Test
    public void tokenWithoutNbfIsRejected() {
        JwtBuilder token = Jwts.builder().setSubject(JWT_USER).setExpiration(new Date(System.currentTimeMillis() + 3_600_000));

        try (TestRestClient client = LIST_CLUSTER.getRestClient(bearer(token))) {
            client.getAuthInfo().assertStatusCode(401);
        }
    }

    @Test
    public void tokenWithNullExpIsRejected() {
        JwtBuilder token = Jwts.builder().setPayload("{\"sub\":\"" + JWT_USER + "\",\"exp\":null}");

        try (TestRestClient client = LIST_CLUSTER.getRestClient(bearer(token))) {
            client.getAuthInfo().assertStatusCode(401);
        }
    }

    @Test
    public void requiredClaimsAsMapDisablesTheJwtAuthDomain() {
        // If the map were silently ignored, a token without exp would be accepted
        JwtBuilder tokenWithoutExp = Jwts.builder().setSubject(JWT_USER);
        try (TestRestClient client = MAP_CLUSTER.getRestClient(bearer(tokenWithoutExp))) {
            client.getAuthInfo().assertStatusCode(401);
        }
        try (TestRestClient client = MAP_CLUSTER.getRestClient(bearer(tokenWithExpAndNbf()))) {
            client.getAuthInfo().assertStatusCode(401);
        }
        // The other authentication domains keep working
        try (TestRestClient client = MAP_CLUSTER.getRestClient(ADMIN_USER)) {
            client.getAuthInfo().assertStatusCode(200);
        }
    }

    @Test
    public void requiredClaimsWithBlankEntryDisablesTheJwtAuthDomain() {
        try (TestRestClient client = BLANK_ENTRY_CLUSTER.getRestClient(bearer(tokenWithExpAndNbf()))) {
            client.getAuthInfo().assertStatusCode(401);
        }
        // The other authentication domains keep working
        try (TestRestClient client = BLANK_ENTRY_CLUSTER.getRestClient(ADMIN_USER)) {
            client.getAuthInfo().assertStatusCode(200);
        }
    }
}
