/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security;

import java.util.concurrent.TimeUnit;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.AuthFailureListeners;
import org.opensearch.test.framework.RateLimiting;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.test.framework.cluster.TestRestClientConfiguration;
import org.opensearch.test.framework.log.LogsRule;

import static org.apache.http.HttpStatus.SC_OK;
import static org.apache.http.HttpStatus.SC_UNAUTHORIZED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL_WITHOUT_CHALLENGE;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.cluster.TestRestClientConfiguration.userWithSourceIp;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class IpBruteForceAttacksPreventionTests {
    static final User USER_1 = new User("simple-user-1").roles(ALL_ACCESS);
    static final User USER_2 = new User("simple-user-2").roles(ALL_ACCESS);

    public static final int ALLOWED_TRIES = 3;
    public static final int TIME_WINDOW_SECONDS = 3;

    public static final String CLIENT_IP_2 = "127.0.0.2";
    public static final String CLIENT_IP_3 = "127.0.0.3";
    public static final String CLIENT_IP_4 = "127.0.0.4";
    public static final String CLIENT_IP_5 = "127.0.0.5";
    public static final String CLIENT_IP_6 = "127.0.0.6";
    public static final String CLIENT_IP_7 = "127.0.0.7";
    public static final String CLIENT_IP_8 = "127.0.0.8";
    public static final String CLIENT_IP_9 = "127.0.0.9";

    static final AuthFailureListeners listener = new AuthFailureListeners().addRateLimit(
        new RateLimiting("internal_authentication_backend_limiting").type("ip")
            .allowedTries(ALLOWED_TRIES)
            .timeWindowSeconds(TIME_WINDOW_SECONDS)
            .blockExpirySeconds(2)
            .maxBlockedClients(500)
            .maxTrackedClients(500)
    );

    @Rule
    public LocalCluster cluster = createCluster();

    public LocalCluster createCluster() {
        return new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
            .anonymousAuth(false)
            .authFailureListeners(listener)
            .authc(AUTHC_HTTPBASIC_INTERNAL_WITHOUT_CHALLENGE)
            .users(USER_1, USER_2)
            .build();
    }

    @Rule
    public LogsRule logsRule = new LogsRule("org.opensearch.security.auth.BackendRegistry");

    @Test
    public void shouldAuthenticateUserWhenBlockadeIsNotActive() {
        try (TestRestClient client = cluster.createGenericClientRestClient(userWithSourceIp(USER_1, CLIENT_IP_2))) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(SC_OK);
        }
    }

    @Test
    public void shouldBlockIpAddress() {
        authenticateUserWithIncorrectPassword(CLIENT_IP_3, USER_2, ALLOWED_TRIES);
        try (TestRestClient client = cluster.createGenericClientRestClient(userWithSourceIp(USER_2, CLIENT_IP_3))) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(SC_UNAUTHORIZED);
            logsRule.assertThatContain("Rejecting REST request because of blocked address: /" + CLIENT_IP_3);
        }
    }

    @Test
    public void shouldBlockUsersWhoUseTheSameIpAddress() {
        authenticateUserWithIncorrectPassword(CLIENT_IP_4, USER_1, ALLOWED_TRIES);
        try (TestRestClient client = cluster.createGenericClientRestClient(userWithSourceIp(USER_2, CLIENT_IP_4))) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(SC_UNAUTHORIZED);
            logsRule.assertThatContain("Rejecting REST request because of blocked address: /" + CLIENT_IP_4);
        }
    }

    @Test
    public void testUserShouldBeAbleToAuthenticateFromAnotherNotBlockedIpAddress() {
        authenticateUserWithIncorrectPassword(CLIENT_IP_5, USER_1, ALLOWED_TRIES);
        try (TestRestClient client = cluster.createGenericClientRestClient(userWithSourceIp(USER_1, CLIENT_IP_6))) {
            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(SC_OK);
        }
    }

    @Test
    public void shouldNotBlockIpWhenFailureAuthenticationCountIsLessThanAllowedTries() {
        authenticateUserWithIncorrectPassword(CLIENT_IP_7, USER_1, ALLOWED_TRIES - 1);
        try (TestRestClient client = cluster.createGenericClientRestClient(userWithSourceIp(USER_1, CLIENT_IP_7))) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(SC_OK);
        }
    }

    @Test
    public void shouldBlockIpWhenFailureAuthenticationCountIsGreaterThanAllowedTries() {
        authenticateUserWithIncorrectPassword(CLIENT_IP_8, USER_1, ALLOWED_TRIES * 2);
        try (TestRestClient client = cluster.createGenericClientRestClient(userWithSourceIp(USER_1, CLIENT_IP_8))) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(SC_UNAUTHORIZED);
            logsRule.assertThatContain("Rejecting REST request because of blocked address: /" + CLIENT_IP_8);
        }
    }

    @Test
    public void shouldReleaseIpAddressLock() throws InterruptedException {
        authenticateUserWithIncorrectPassword(CLIENT_IP_9, USER_1, ALLOWED_TRIES * 2);
        TimeUnit.SECONDS.sleep(TIME_WINDOW_SECONDS);
        try (TestRestClient client = cluster.createGenericClientRestClient(userWithSourceIp(USER_1, CLIENT_IP_9))) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(SC_OK);
            logsRule.assertThatContain("Rejecting REST request because of blocked address: /" + CLIENT_IP_9);
        }
    }

    void authenticateUserWithIncorrectPassword(String sourceIpAddress, User user, int numberOfRequests) {
        var clientConfiguration = new TestRestClientConfiguration().username(user.getName())
            .password("incorrect password")
            .sourceInetAddress(sourceIpAddress);
        try (TestRestClient client = cluster.createGenericClientRestClient(clientConfiguration)) {
            for (int i = 0; i < numberOfRequests; ++i) {
                HttpResponse response = client.getAuthInfo();

                response.assertStatusCode(SC_UNAUTHORIZED);
            }
        }
    }
}
