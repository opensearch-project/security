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

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class AnonymousAuthenticationTest {

    private static final String DEFAULT_ANONYMOUS_USER_NAME = "opendistro_security_anonymous";
    private static final String DEFAULT_ANONYMOUS_USER_BACKEND_ROLE_NAME = "opendistro_security_anonymous_backendrole";

    /**
    * Custom role assigned to the anonymous user via {@link #ANONYMOUS_USER_CUSTOM_ROLE_MAPPING}
    */
    private static final TestSecurityConfig.Role ANONYMOUS_USER_CUSTOM_ROLE = new TestSecurityConfig.Role("anonymous_user_custom_role");

    /**
    * Maps {@link #ANONYMOUS_USER_CUSTOM_ROLE} to {@link #DEFAULT_ANONYMOUS_USER_BACKEND_ROLE_NAME}
    */
    private static final TestSecurityConfig.RoleMapping ANONYMOUS_USER_CUSTOM_ROLE_MAPPING = new TestSecurityConfig.RoleMapping(
        ANONYMOUS_USER_CUSTOM_ROLE.getName()
    ).backendRoles(DEFAULT_ANONYMOUS_USER_BACKEND_ROLE_NAME);

    /**
    * User who is stored in the internal user database and can authenticate
    */
    private static final TestSecurityConfig.User EXISTING_USER = new TestSecurityConfig.User("existing_user").roles(
        new TestSecurityConfig.Role("existing_user")
    );

    /**
    * User who is not stored in the internal user database and can not authenticate
    */
    private static final TestSecurityConfig.User NOT_EXISTING_USER = new TestSecurityConfig.User("not_existing_user").roles(
        new TestSecurityConfig.Role("not_existing_user")
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(true)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(EXISTING_USER)
        .roles(ANONYMOUS_USER_CUSTOM_ROLE)
        .rolesMapping(ANONYMOUS_USER_CUSTOM_ROLE_MAPPING)
        .build();

    private static final String USER_NAME_POINTER = "/user_name";
    private static final String BACKEND_ROLES_POINTER = "/backend_roles";
    private static final String ROLES_POINTER = "/roles";

    @Test
    public void shouldAuthenticate_positive_anonymousUser() {
        try (TestRestClient client = cluster.getRestClient()) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);

            String username = response.getTextFromJsonBody(USER_NAME_POINTER);
            assertThat(username, equalTo(DEFAULT_ANONYMOUS_USER_NAME));

            List<String> backendRoles = response.getTextArrayFromJsonBody(BACKEND_ROLES_POINTER);
            assertThat(backendRoles, hasSize(1));
            assertThat(backendRoles, contains(DEFAULT_ANONYMOUS_USER_BACKEND_ROLE_NAME));

            List<String> roles = response.getTextArrayFromJsonBody(ROLES_POINTER);
            assertThat(roles, hasSize(1));
            assertThat(roles, contains(ANONYMOUS_USER_CUSTOM_ROLE.getName()));
        }
    }

    @Test
    public void shouldAuthenticate_positive_existingUser() {
        try (TestRestClient client = cluster.getRestClient(EXISTING_USER)) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);

            String username = response.getTextFromJsonBody(USER_NAME_POINTER);
            assertThat(username, equalTo(EXISTING_USER.getName()));

            List<String> backendRoles = response.getTextArrayFromJsonBody(BACKEND_ROLES_POINTER);
            assertThat(backendRoles, hasSize(0));

            List<String> roles = response.getTextArrayFromJsonBody(ROLES_POINTER);
            assertThat(roles, hasSize(EXISTING_USER.getRoleNames().size()));
            assertThat(roles, containsInAnyOrder(EXISTING_USER.getRoleNames().toArray()));
        }
    }

    @Test
    public void shouldAuthenticate_negative_notExistingUser() {
        try (TestRestClient client = cluster.getRestClient(NOT_EXISTING_USER)) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
        }
    }
}
