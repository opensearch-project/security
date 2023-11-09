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
import org.junit.ClassRule;
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
import org.opensearch.test.framework.log.LogsRule;

import static org.apache.http.HttpStatus.SC_OK;
import static org.apache.http.HttpStatus.SC_UNAUTHORIZED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class UserBruteForceAttacksPreventionTests {

    private static final User USER_1 = new User("simple-user-1").roles(ALL_ACCESS);
    private static final User USER_2 = new User("simple-user-2").roles(ALL_ACCESS);
    private static final User USER_3 = new User("simple-user-3").roles(ALL_ACCESS);
    private static final User USER_4 = new User("simple-user-4").roles(ALL_ACCESS);
    private static final User USER_5 = new User("simple-user-5").roles(ALL_ACCESS);

    public static final int ALLOWED_TRIES = 3;
    public static final int TIME_WINDOW_SECONDS = 3;
    private static final AuthFailureListeners listener = new AuthFailureListeners().addRateLimit(
        new RateLimiting("internal_authentication_backend_limiting").type("username")
            .authenticationBackend("intern")
            .allowedTries(ALLOWED_TRIES)
            .timeWindowSeconds(TIME_WINDOW_SECONDS)
            .blockExpirySeconds(2)
            .maxBlockedClients(500)
            .maxTrackedClients(500)
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authFailureListeners(listener)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_1, USER_2, USER_3, USER_4, USER_5)
        .build();

    @Rule
    public LogsRule logsRule = new LogsRule("org.opensearch.security.auth.BackendRegistry");

    @Test
    public void shouldAuthenticateUserWhenBlockadeIsNotActive() {
        try (TestRestClient client = cluster.getRestClient(USER_1)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(SC_OK);
        }
    }

    @Test
    public void shouldBlockUserWhenNumberOfFailureLoginAttemptIsEqualToLimit() {
        authenticateUserWithIncorrectPassword(USER_2, ALLOWED_TRIES);
        try (TestRestClient client = cluster.getRestClient(USER_2)) {
            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(SC_UNAUTHORIZED);
        }
        // Rejecting REST request because of blocked user:
        logsRule.assertThatContain("Rejecting REST request because of blocked user: " + USER_2.getName());
    }

    @Test
    public void shouldBlockUserWhenNumberOfFailureLoginAttemptIsGreaterThanLimit() {
        authenticateUserWithIncorrectPassword(USER_3, ALLOWED_TRIES * 2);
        try (TestRestClient client = cluster.getRestClient(USER_3)) {
            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(SC_UNAUTHORIZED);
        }
        logsRule.assertThatContain("Rejecting REST request because of blocked user: " + USER_3.getName());
    }

    @Test
    public void shouldNotBlockUserWhenNumberOfLoginAttemptIsBelowLimit() {
        authenticateUserWithIncorrectPassword(USER_4, ALLOWED_TRIES - 1);
        try (TestRestClient client = cluster.getRestClient(USER_4)) {
            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(SC_OK);
        }
    }

    @Test
    public void shouldReleaseLock() throws InterruptedException {
        authenticateUserWithIncorrectPassword(USER_5, ALLOWED_TRIES);
        try (TestRestClient client = cluster.getRestClient(USER_5)) {
            HttpResponse response = client.getAuthInfo();
            response.assertStatusCode(SC_UNAUTHORIZED);
            TimeUnit.SECONDS.sleep(TIME_WINDOW_SECONDS);

            response = client.getAuthInfo();

            response.assertStatusCode(SC_OK);
        }
        logsRule.assertThatContain("Rejecting REST request because of blocked user: " + USER_5.getName());
    }

    private static void authenticateUserWithIncorrectPassword(User user, int numberOfAttempts) {
        try (TestRestClient client = cluster.getRestClient(user.getName(), "incorrect password")) {
            for (int i = 0; i < numberOfAttempts; ++i) {
                HttpResponse response = client.getAuthInfo();
                response.assertStatusCode(SC_UNAUTHORIZED);
            }
        }
    }
}
