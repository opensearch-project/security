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
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.client.Client;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AuthenticationBackend;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.HttpAuthenticator;
import org.opensearch.test.framework.XffConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.test.framework.cluster.TestRestClientConfiguration;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.security.Song.TITLE_MAGNUM_OPUS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

/**
* Class used to run tests defined in supper class and adds tests specific for <code>extended-proxy</code> authentication.
*/
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ExtendedProxyAuthenticationTest extends CommonProxyAuthenticationTests {

    public static final String ID_ONE_1 = "one#1";
    public static final String ID_TWO_2 = "two#2";
    public static final Map<String, Object> PROXY_AUTHENTICATOR_CONFIG = Map.of(
        "user_header",
        HEADER_PROXY_USER,
        "roles_header",
        HEADER_PROXY_ROLES,
        "attr_header_prefix",
        HEADER_PREFIX_CUSTOM_ATTRIBUTES
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .xff(new XffConfig(true).internalProxiesRegexp("127\\.0\\.0\\.10"))
        .authc(
            new AuthcDomain("proxy_auth_domain", -5, true).httpAuthenticator(
                new HttpAuthenticator("extended-proxy").challenge(false).config(PROXY_AUTHENTICATOR_CONFIG)
            ).backend(new AuthenticationBackend("noop"))
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN)
        .roles(ROLE_ALL_INDEX_SEARCH, ROLE_PERSONAL_INDEX_SEARCH)
        .rolesMapping(ROLES_MAPPING_CAPTAIN, ROLES_MAPPING_FIRST_MATE)
        .build();

    @Override
    protected LocalCluster getCluster() {
        return cluster;
    }

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.prepareIndex(PERSONAL_INDEX_NAME_SPOCK).setId(ID_ONE_1).setRefreshPolicy(IMMEDIATE).setSource(SONGS[0].asMap()).get();
            client.prepareIndex(PERSONAL_INDEX_NAME_KIRK).setId(ID_TWO_2).setRefreshPolicy(IMMEDIATE).setSource(SONGS[1].asMap()).get();
        }
    }

    @Test
    @Override
    public void shouldAuthenticateWithBasicAuthWhenProxyAuthenticationIsConfigured() {
        super.shouldAuthenticateWithBasicAuthWhenProxyAuthenticationIsConfigured();
    }

    @Test
    @Override
    public void shouldAuthenticateWithProxy_positiveUserKirk() throws IOException {
        super.shouldAuthenticateWithProxy_positiveUserKirk();
    }

    @Test
    @Override
    public void shouldAuthenticateWithProxy_positiveUserSpock() throws IOException {
        super.shouldAuthenticateWithProxy_positiveUserSpock();
    }

    @Test
    @Override
    public void shouldAuthenticateWithProxy_negativeWhenXffHeaderIsMissing() throws IOException {
        super.shouldAuthenticateWithProxy_negativeWhenXffHeaderIsMissing();
    }

    @Test
    @Override
    public void shouldAuthenticateWithProxy_negativeWhenUserNameHeaderIsMissing() throws IOException {
        super.shouldAuthenticateWithProxy_negativeWhenUserNameHeaderIsMissing();
    }

    @Test
    @Override
    public void shouldAuthenticateWithProxyWhenRolesHeaderIsMissing() throws IOException {
        super.shouldAuthenticateWithProxyWhenRolesHeaderIsMissing();
    }

    @Test
    @Override
    public void shouldAuthenticateWithProxy_negativeWhenRequestWasNotSendByProxy() throws IOException {
        super.shouldAuthenticateWithProxy_negativeWhenRequestWasNotSendByProxy();
    }

    @Test
    @Override
    public void shouldRetrieveEmptyListOfRoles() throws IOException {
        super.shouldRetrieveEmptyListOfRoles();
    }

    @Test
    @Override
    public void shouldRetrieveSingleRoleFirstMate() throws IOException {
        super.shouldRetrieveSingleRoleFirstMate();
    }

    @Test
    @Override
    public void shouldRetrieveSingleRoleCaptain() throws IOException {
        super.shouldRetrieveSingleRoleCaptain();
    }

    @Test
    @Override
    public void shouldRetrieveMultipleRoles() throws IOException {
        super.shouldRetrieveMultipleRoles();
    }

    // tests specific for extended proxy authentication

    @Test
    public void shouldRetrieveCustomAttributeNameDepartment() throws IOException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_PROXY)
        )
            .header(HEADER_FORWARDED_FOR, IP_CLIENT)
            .header(HEADER_PROXY_USER, USER_SPOCK)
            .header(HEADER_PROXY_ROLES, BACKEND_ROLE_CAPTAIN)
            .header(HEADER_DEPARTMENT, DEPARTMENT_BRIDGE);
        try (TestRestClient client = cluster.createGenericClientRestClient(testRestClientConfiguration)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            List<String> customAttributes = response.getTextArrayFromJsonBody(POINTER_CUSTOM_ATTRIBUTES);
            assertThat(customAttributes, hasSize(2));
            assertThat(customAttributes, containsInAnyOrder(USER_ATTRIBUTE_USERNAME_NAME, USER_ATTRIBUTE_DEPARTMENT_NAME));
        }
    }

    @Test
    public void shouldRetrieveCustomAttributeNameSkills() throws IOException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_PROXY)
        )
            .header(HEADER_FORWARDED_FOR, IP_CLIENT)
            .header(HEADER_PROXY_USER, USER_SPOCK)
            .header(HEADER_PROXY_ROLES, BACKEND_ROLE_CAPTAIN)
            .header(HEADER_SKILLS, "bilocation");
        try (TestRestClient client = cluster.createGenericClientRestClient(testRestClientConfiguration)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            List<String> customAttributes = response.getTextArrayFromJsonBody(POINTER_CUSTOM_ATTRIBUTES);
            assertThat(customAttributes, hasSize(2));
            assertThat(customAttributes, containsInAnyOrder(USER_ATTRIBUTE_USERNAME_NAME, USER_ATTRIBUTE_SKILLS_NAME));
        }
    }

    @Test
    public void shouldRetrieveMultipleCustomAttributes() throws IOException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_PROXY)
        )
            .header(HEADER_FORWARDED_FOR, IP_CLIENT)
            .header(HEADER_PROXY_USER, USER_SPOCK)
            .header(HEADER_PROXY_ROLES, BACKEND_ROLE_CAPTAIN)
            .header(HEADER_DEPARTMENT, DEPARTMENT_BRIDGE)
            .header(HEADER_SKILLS, "bilocation");
        try (TestRestClient client = cluster.createGenericClientRestClient(testRestClientConfiguration)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            List<String> customAttributes = response.getTextArrayFromJsonBody(POINTER_CUSTOM_ATTRIBUTES);
            assertThat(customAttributes, hasSize(3));
            assertThat(
                customAttributes,
                containsInAnyOrder(USER_ATTRIBUTE_DEPARTMENT_NAME, USER_ATTRIBUTE_USERNAME_NAME, USER_ATTRIBUTE_SKILLS_NAME)
            );
        }
    }

    @Test
    public void shouldRetrieveUserRolesAndAttributesSoThatAccessToPersonalIndexIsPossible_positive() throws UnknownHostException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_PROXY)
        )
            .header(HEADER_FORWARDED_FOR, IP_CLIENT)
            .header(HEADER_PROXY_USER, USER_SPOCK)
            .header(HEADER_PROXY_ROLES, BACKEND_ROLE_CAPTAIN)
            .header(HEADER_DEPARTMENT, DEPARTMENT_BRIDGE);
        try (TestRestClient client = cluster.createGenericClientRestClient(testRestClientConfiguration)) {

            HttpResponse response = client.get(PERSONAL_INDEX_NAME_SPOCK + "/_search");

            response.assertStatusCode(200);
            assertThat(response.getLongFromJsonBody(POINTER_TOTAL_HITS), equalTo(1L));
            assertThat(response.getTextFromJsonBody(POINTER_FIRST_DOCUMENT_ID), equalTo(ID_ONE_1));
            assertThat(response.getTextFromJsonBody(POINTER_FIRST_DOCUMENT_INDEX), equalTo(PERSONAL_INDEX_NAME_SPOCK));
            assertThat(response.getTextFromJsonBody(POINTER_FIRST_DOCUMENT_SOURCE_TITLE), equalTo(TITLE_MAGNUM_OPUS));
        }
    }

    @Test
    public void shouldRetrieveUserRolesAndAttributesSoThatAccessToPersonalIndexIsPossible_negative() throws UnknownHostException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_PROXY)
        )
            .header(HEADER_FORWARDED_FOR, IP_CLIENT)
            .header(HEADER_PROXY_USER, USER_SPOCK)
            .header(HEADER_PROXY_ROLES, BACKEND_ROLE_CAPTAIN)
            .header(HEADER_DEPARTMENT, DEPARTMENT_BRIDGE);
        try (TestRestClient client = cluster.createGenericClientRestClient(testRestClientConfiguration)) {

            HttpResponse response = client.get(PERSONAL_INDEX_NAME_KIRK + "/_search");

            response.assertStatusCode(403);
        }
    }

}
