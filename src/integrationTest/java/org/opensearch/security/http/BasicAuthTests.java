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

import java.util.List;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpHeaders;
import org.hamcrest.Matchers;
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
import static org.hamcrest.Matchers.containsStringIgnoringCase;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class BasicAuthTests {
    static final User TEST_USER = new User("test_user").password("s3cret");

    public static final String CUSTOM_ATTRIBUTE_NAME = "superhero";
    static final User SUPER_USER = new User("super-user").password("super-password").attr(CUSTOM_ATTRIBUTE_NAME, "true");
    public static final String NOT_EXISTING_USER = "not-existing-user";
    public static final String INVALID_PASSWORD = "secret-password";

    public static final AuthcDomain AUTHC_DOMAIN = new AuthcDomain("basic", 0).httpAuthenticatorWithChallenge("basic").backend("internal");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_DOMAIN)
        .users(TEST_USER, SUPER_USER)
        .build();

    @Test
    public void shouldRespondWith401WhenUserDoesNotExist() {
        try (TestRestClient client = cluster.getRestClient(NOT_EXISTING_USER, INVALID_PASSWORD)) {
            HttpResponse response = client.getAuthInfo();

            assertThat(response, is(notNullValue()));
            response.assertStatusCode(SC_UNAUTHORIZED);
        }
    }

    @Test
    public void shouldRespondWith401WhenUserNameIsIncorrect() {
        try (TestRestClient client = cluster.getRestClient(NOT_EXISTING_USER, TEST_USER.getPassword())) {
            HttpResponse response = client.getAuthInfo();

            assertThat(response, is(notNullValue()));
            response.assertStatusCode(SC_UNAUTHORIZED);
        }
    }

    @Test
    public void shouldRespondWith401WhenPasswordIsIncorrect() {
        try (TestRestClient client = cluster.getRestClient(TEST_USER.getName(), INVALID_PASSWORD)) {
            HttpResponse response = client.getAuthInfo();

            assertThat(response, is(notNullValue()));
            response.assertStatusCode(SC_UNAUTHORIZED);
        }
    }

    @Test
    public void shouldRespondWith200WhenCredentialsAreCorrect() {
        try (TestRestClient client = cluster.getRestClient(TEST_USER)) {

            HttpResponse response = client.getAuthInfo();

            assertThat(response, is(notNullValue()));
            response.assertStatusCode(SC_OK);
        }
    }

    @Test
    public void testBrowserShouldRequestForCredentials() {
        try (TestRestClient client = cluster.getRestClient()) {

            HttpResponse response = client.getAuthInfo();

            assertThat(response, is(notNullValue()));
            response.assertStatusCode(SC_UNAUTHORIZED);
            assertThatBrowserAskUserForCredentials(response);
        }
    }

    @Test
    public void shouldRespondWithChallengeWhenNoCredentialsArePresent() {
        try (TestRestClient client = cluster.getRestClient()) {
            HttpResponse response = client.getAuthInfo();

            assertThat(response, is(notNullValue()));
            response.assertStatusCode(SC_UNAUTHORIZED);
            assertThat(response.getHeader("WWW-Authenticate"), is(notNullValue()));
            assertThat(response.getHeader("WWW-Authenticate").getValue(), equalTo("Basic realm=\"OpenSearch Security\""));
            assertThat(response.getBody(), equalTo("Unauthorized"));
        }
    }

    @Test
    public void testUserShouldNotHaveAssignedCustomAttributes() {
        try (TestRestClient client = cluster.getRestClient(TEST_USER)) {

            HttpResponse response = client.getAuthInfo();

            assertThat(response, is(notNullValue()));
            response.assertStatusCode(SC_OK);
            AuthInfo authInfo = response.getBodyAs(AuthInfo.class);
            assertThat(authInfo, is(notNullValue()));
            assertThat(authInfo.getCustomAttributeNames(), is(notNullValue()));
            assertThat(authInfo.getCustomAttributeNames(), hasSize(0));
        }
    }

    @Test
    public void testUserShouldHaveAssignedCustomAttributes() {
        try (TestRestClient client = cluster.getRestClient(SUPER_USER)) {

            HttpResponse response = client.getAuthInfo();

            assertThat(response, is(notNullValue()));
            response.assertStatusCode(SC_OK);
            AuthInfo authInfo = response.getBodyAs(AuthInfo.class);
            assertThat(authInfo, is(notNullValue()));
            List<String> customAttributeNames = authInfo.getCustomAttributeNames();
            assertThat(customAttributeNames, is(notNullValue()));
            assertThat(customAttributeNames, hasSize(1));
            assertThat(customAttributeNames.get(0), Matchers.equalTo("attr.internal." + CUSTOM_ATTRIBUTE_NAME));
        }
    }

    private void assertThatBrowserAskUserForCredentials(HttpResponse response) {
        String reason = "Browser does not ask user for credentials";
        assertThat(reason, response.containHeader(HttpHeaders.WWW_AUTHENTICATE), equalTo(true));
        assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE).getValue(), containsStringIgnoringCase("basic"));
    }
}
