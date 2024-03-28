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
import java.util.List;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClientConfiguration;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
* Class defines common tests for proxy and extended-proxy authentication. Subclasses are used to run tests.
*/
abstract class CommonProxyAuthenticationTests {

    protected static final String RESOURCE_AUTH_INFO = "_opendistro/_security/authinfo";
    protected static final TestSecurityConfig.User USER_ADMIN = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    protected static final String ATTRIBUTE_DEPARTMENT = "department";
    protected static final String ATTRIBUTE_SKILLS = "skills";

    protected static final String USER_ATTRIBUTE_DEPARTMENT_NAME = "attr.proxy." + ATTRIBUTE_DEPARTMENT;
    protected static final String USER_ATTRIBUTE_SKILLS_NAME = "attr.proxy." + ATTRIBUTE_SKILLS;
    protected static final String USER_ATTRIBUTE_USERNAME_NAME = "attr.proxy.username";

    protected static final String HEADER_PREFIX_CUSTOM_ATTRIBUTES = "x-custom-attr";
    protected static final String HEADER_PROXY_USER = "x-proxy-user";
    protected static final String HEADER_PROXY_ROLES = "x-proxy-roles";
    protected static final String HEADER_FORWARDED_FOR = "X-Forwarded-For";
    protected static final String HEADER_DEPARTMENT = HEADER_PREFIX_CUSTOM_ATTRIBUTES + ATTRIBUTE_DEPARTMENT;
    protected static final String HEADER_SKILLS = HEADER_PREFIX_CUSTOM_ATTRIBUTES + ATTRIBUTE_SKILLS;

    protected static final String IP_PROXY = "127.0.0.10";
    protected static final String IP_NON_PROXY = "127.0.0.5";
    protected static final String IP_CLIENT = "127.0.0.1";

    protected static final String USER_KIRK = "kirk";
    protected static final String USER_SPOCK = "spock";

    protected static final String BACKEND_ROLE_FIRST_MATE = "firstMate";
    protected static final String BACKEND_ROLE_CAPTAIN = "captain";
    protected static final String DEPARTMENT_BRIDGE = "bridge";

    protected static final String PERSONAL_INDEX_NAME_PATTERN = "personal-${"
        + USER_ATTRIBUTE_DEPARTMENT_NAME
        + "}-${"
        + USER_ATTRIBUTE_USERNAME_NAME
        + "}";
    protected static final String PERSONAL_INDEX_NAME_SPOCK = "personal-" + DEPARTMENT_BRIDGE + "-" + USER_SPOCK;
    protected static final String PERSONAL_INDEX_NAME_KIRK = "personal-" + DEPARTMENT_BRIDGE + "-" + USER_KIRK;

    protected static final String POINTER_USERNAME = "/user_name";
    protected static final String POINTER_BACKEND_ROLES = "/backend_roles";
    protected static final String POINTER_ROLES = "/roles";
    protected static final String POINTER_CUSTOM_ATTRIBUTES = "/custom_attribute_names";
    protected static final String POINTER_TOTAL_HITS = "/hits/total/value";
    protected static final String POINTER_FIRST_DOCUMENT_ID = "/hits/hits/0/_id";
    protected static final String POINTER_FIRST_DOCUMENT_INDEX = "/hits/hits/0/_index";
    protected static final String POINTER_FIRST_DOCUMENT_SOURCE_TITLE = "/hits/hits/0/_source/title";

    protected static final TestSecurityConfig.Role ROLE_ALL_INDEX_SEARCH = new TestSecurityConfig.Role("all-index-search").indexPermissions(
        "indices:data/read/search"
    ).on("*");

    protected static final TestSecurityConfig.Role ROLE_PERSONAL_INDEX_SEARCH = new TestSecurityConfig.Role("personal-index-search")
        .indexPermissions("indices:data/read/search")
        .on(PERSONAL_INDEX_NAME_PATTERN);

    protected static final TestSecurityConfig.RoleMapping ROLES_MAPPING_CAPTAIN = new TestSecurityConfig.RoleMapping(
        ROLE_PERSONAL_INDEX_SEARCH.getName()
    ).backendRoles(BACKEND_ROLE_CAPTAIN);

    protected static final TestSecurityConfig.RoleMapping ROLES_MAPPING_FIRST_MATE = new TestSecurityConfig.RoleMapping(
        ROLE_ALL_INDEX_SEARCH.getName()
    ).backendRoles(BACKEND_ROLE_FIRST_MATE);

    protected abstract LocalCluster getCluster();

    protected void shouldAuthenticateWithBasicAuthWhenProxyAuthenticationIsConfigured() {
        try (TestRestClient client = getCluster().getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.get(RESOURCE_AUTH_INFO);

            response.assertStatusCode(200);
        }
    }

    protected void shouldAuthenticateWithProxy_positiveUserKirk() throws IOException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_PROXY)
        ).header(HEADER_FORWARDED_FOR, IP_CLIENT).header(HEADER_PROXY_USER, USER_KIRK).header(HEADER_PROXY_ROLES, BACKEND_ROLE_CAPTAIN);
        try (TestRestClient client = getCluster().createGenericClientRestClient(testRestClientConfiguration)) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_KIRK));
        }
    }

    protected void shouldAuthenticateWithProxy_positiveUserSpock() throws IOException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_PROXY)
        ).header(HEADER_FORWARDED_FOR, IP_CLIENT).header(HEADER_PROXY_USER, USER_SPOCK).header(HEADER_PROXY_ROLES, BACKEND_ROLE_FIRST_MATE);
        try (TestRestClient client = getCluster().createGenericClientRestClient(testRestClientConfiguration)) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_SPOCK));
        }
    }

    protected void shouldAuthenticateWithProxy_negativeWhenXffHeaderIsMissing() throws IOException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_PROXY)
        ).header(HEADER_PROXY_USER, USER_KIRK).header(HEADER_PROXY_ROLES, BACKEND_ROLE_CAPTAIN);
        try (TestRestClient client = getCluster().createGenericClientRestClient(testRestClientConfiguration)) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
        }
    }

    protected void shouldAuthenticateWithProxy_negativeWhenUserNameHeaderIsMissing() throws IOException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_PROXY)
        ).header(HEADER_FORWARDED_FOR, IP_CLIENT).header(HEADER_PROXY_ROLES, BACKEND_ROLE_CAPTAIN);
        try (TestRestClient client = getCluster().createGenericClientRestClient(testRestClientConfiguration)) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
        }
    }

    protected void shouldAuthenticateWithProxyWhenRolesHeaderIsMissing() throws IOException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_PROXY)
        ).header(HEADER_FORWARDED_FOR, IP_CLIENT).header(HEADER_PROXY_USER, USER_KIRK);
        try (TestRestClient client = getCluster().createGenericClientRestClient(testRestClientConfiguration)) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_KIRK));
        }
    }

    protected void shouldAuthenticateWithProxy_negativeWhenRequestWasNotSendByProxy() throws IOException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_NON_PROXY)
        ).header(HEADER_FORWARDED_FOR, IP_CLIENT).header(HEADER_PROXY_USER, USER_KIRK);
        try (TestRestClient client = getCluster().createGenericClientRestClient(testRestClientConfiguration)) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
        }
    }

    protected void shouldRetrieveEmptyListOfRoles() throws IOException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_PROXY)
        ).header(HEADER_FORWARDED_FOR, IP_CLIENT).header(HEADER_PROXY_USER, USER_SPOCK);
        try (TestRestClient client = getCluster().createGenericClientRestClient(testRestClientConfiguration)) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            List<String> backendRoles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(backendRoles, hasSize(0));
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_ROLES);
            assertThat(roles, hasSize(0));
        }
    }

    protected void shouldRetrieveSingleRoleFirstMate() throws IOException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_PROXY)
        ).header(HEADER_FORWARDED_FOR, IP_CLIENT).header(HEADER_PROXY_USER, USER_SPOCK).header(HEADER_PROXY_ROLES, BACKEND_ROLE_FIRST_MATE);
        try (TestRestClient client = getCluster().createGenericClientRestClient(testRestClientConfiguration)) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            List<String> backendRoles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(backendRoles, hasSize(1));
            assertThat(backendRoles, contains(BACKEND_ROLE_FIRST_MATE));
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_ROLES);
            assertThat(roles, hasSize(1));
            assertThat(roles, contains(ROLE_ALL_INDEX_SEARCH.getName()));
        }
    }

    protected void shouldRetrieveSingleRoleCaptain() throws IOException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_PROXY)
        ).header(HEADER_FORWARDED_FOR, IP_CLIENT).header(HEADER_PROXY_USER, USER_SPOCK).header(HEADER_PROXY_ROLES, BACKEND_ROLE_CAPTAIN);
        try (TestRestClient client = getCluster().createGenericClientRestClient(testRestClientConfiguration)) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            List<String> backendRoles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(backendRoles, hasSize(1));
            assertThat(backendRoles, contains(BACKEND_ROLE_CAPTAIN));
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_ROLES);
            assertThat(roles, hasSize(1));
            assertThat(roles, contains(ROLE_PERSONAL_INDEX_SEARCH.getName()));
        }
    }

    protected void shouldRetrieveMultipleRoles() throws IOException {
        TestRestClientConfiguration testRestClientConfiguration = new TestRestClientConfiguration().sourceInetAddress(
            InetAddress.getByName(IP_PROXY)
        )
            .header(HEADER_FORWARDED_FOR, IP_CLIENT)
            .header(HEADER_PROXY_USER, USER_SPOCK)
            .header(HEADER_PROXY_ROLES, BACKEND_ROLE_CAPTAIN + "," + BACKEND_ROLE_FIRST_MATE);
        try (TestRestClient client = getCluster().createGenericClientRestClient(testRestClientConfiguration)) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            List<String> backendRoles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(backendRoles, hasSize(2));
            assertThat(backendRoles, containsInAnyOrder(BACKEND_ROLE_CAPTAIN, BACKEND_ROLE_FIRST_MATE));
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_ROLES);
            assertThat(roles, hasSize(2));
            assertThat(roles, containsInAnyOrder(ROLE_PERSONAL_INDEX_SEARCH.getName(), ROLE_ALL_INDEX_SEARCH.getName()));
        }
    }
}
