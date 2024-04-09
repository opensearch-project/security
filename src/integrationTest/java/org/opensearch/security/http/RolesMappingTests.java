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
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.apache.http.HttpStatus.SC_OK;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class RolesMappingTests {
    static final TestSecurityConfig.User USER_A = new TestSecurityConfig.User("userA").password("s3cret").backendRoles("mapsToRoleA");
    static final TestSecurityConfig.User USER_B = new TestSecurityConfig.User("userB").password("P@ssw0rd").backendRoles("mapsToRoleB");

    private static final TestSecurityConfig.Role ROLE_A = new TestSecurityConfig.Role("roleA").clusterPermissions("cluster_all");

    private static final TestSecurityConfig.Role ROLE_B = new TestSecurityConfig.Role("roleB").clusterPermissions("cluster_all");

    public static final TestSecurityConfig.AuthcDomain AUTHC_DOMAIN = new TestSecurityConfig.AuthcDomain("basic", 0)
        .httpAuthenticatorWithChallenge("basic")
        .backend("internal");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_DOMAIN)
        .roles(ROLE_A, ROLE_B)
        .rolesMapping(
            new TestSecurityConfig.RoleMapping(ROLE_A.getName()).backendRoles("mapsToRoleA"),
            new TestSecurityConfig.RoleMapping(ROLE_B.getName()).backendRoles("mapsToRoleB")
        )
        .users(USER_A, USER_B)
        .build();

    @Test
    public void testBackendRoleToRoleMapping() {
        try (TestRestClient client = cluster.getRestClient(USER_A)) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            assertThat(response, is(notNullValue()));
            List<String> roles = response.getTextArrayFromJsonBody("/roles");
            List<String> backendRoles = response.getTextArrayFromJsonBody("/backend_roles");
            assertThat(roles, contains(ROLE_A.getName()));
            assertThat(roles, not(contains(ROLE_B.getName())));
            assertThat(backendRoles, contains("mapsToRoleA"));
            response.assertStatusCode(SC_OK);
        }

        try (TestRestClient client = cluster.getRestClient(USER_B)) {

            TestRestClient.HttpResponse response = client.getAuthInfo();

            assertThat(response, is(notNullValue()));
            List<String> roles = response.getTextArrayFromJsonBody("/roles");
            List<String> backendRoles = response.getTextArrayFromJsonBody("/backend_roles");
            assertThat(roles, contains(ROLE_B.getName()));
            assertThat(roles, not(contains(ROLE_A.getName())));
            assertThat(backendRoles, contains("mapsToRoleB"));
            response.assertStatusCode(SC_OK);
        }
    }
}
