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

import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.apache.http.HttpStatus.SC_OK;
import static org.apache.http.HttpStatus.SC_UNAUTHORIZED;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class BasicWithAnonymousAuthTests {
    static final User TEST_USER = new User("test_user").password("s3cret");

    public static final String CUSTOM_ATTRIBUTE_NAME = "superhero";
    static final User SUPER_USER = new User("super-user").password("super-password").attr(CUSTOM_ATTRIBUTE_NAME, "true");
    public static final String NOT_EXISTING_USER = "not-existing-user";
    public static final String INVALID_PASSWORD = "secret-password";

    public static final AuthcDomain AUTHC_DOMAIN = new AuthcDomain("basic", 0).httpAuthenticatorWithChallenge("basic").backend("internal");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(true)
        .authc(AUTHC_DOMAIN)
        .users(TEST_USER, SUPER_USER)
        .build();

    /** No automatic login post anonymous auth request **/
    @Test
    public void testShouldRespondWith401WhenUserDoesNotExist() {
        try (TestRestClient client = cluster.getRestClient(NOT_EXISTING_USER, INVALID_PASSWORD)) {
            HttpResponse response = client.getAuthInfo();

            assertThat(response, is(notNullValue()));
            response.assertStatusCode(SC_UNAUTHORIZED);
        }
    }

    @Test
    public void testShouldRespondWith401WhenUserNameIsIncorrect() {
        try (TestRestClient client = cluster.getRestClient(NOT_EXISTING_USER, TEST_USER.getPassword())) {
            HttpResponse response = client.getAuthInfo();

            assertThat(response, is(notNullValue()));
            response.assertStatusCode(SC_UNAUTHORIZED);
        }
    }

    @Test
    public void testShouldRespondWith401WhenPasswordIsIncorrect() {
        try (TestRestClient client = cluster.getRestClient(TEST_USER.getName(), INVALID_PASSWORD)) {
            HttpResponse response = client.getAuthInfo();

            assertThat(response, is(notNullValue()));
            response.assertStatusCode(SC_UNAUTHORIZED);
        }
    }

    /** Test `?auth_type=""` param to authinfo request **/
    @Test
    public void testShouldAutomaticallyLoginAsAnonymousIfNoCredentialsArePassed() {
        try (TestRestClient client = cluster.getRestClient()) {

            HttpResponse response = client.getAuthInfo();

            assertThat(response, is(notNullValue()));
            response.assertStatusCode(SC_OK);

            HttpResponse response2 = client.getAuthInfo(Map.of("auth_type", "anonymous"));

            assertThat(response2, is(notNullValue()));
            response2.assertStatusCode(SC_OK);
        }
    }

    @Test
    public void testShouldNotAutomaticallyLoginAsAnonymousIfRequestIsNonAnonymousLogin() {
        try (TestRestClient client = cluster.getRestClient()) {

            HttpResponse response = client.getAuthInfo(Map.of("auth_type", "saml"));

            assertThat(response, is(notNullValue()));
            response.assertStatusCode(SC_UNAUTHORIZED);

            // should contain a redirect link
            assertThat(response.containHeader("WWW-Authenticate"), is(true));
        }
    }
}
