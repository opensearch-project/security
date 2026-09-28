/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource;

import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.opensearch.sample.resource.TestUtils.newCluster;

/**
 * Tests that plugin-provided default-roles.yml roles are loaded as static roles
 * and visible via the security roles API.
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DefaultRolesTests {

    private static final String ROLES_ENDPOINT = "_plugins/_security/api/roles";

    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    @Test
    @SuppressWarnings("unchecked")
    public void testPluginDefaultRolesAreVisibleViaRolesApi() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // List all roles and verify plugin-provided roles are present
            TestRestClient.HttpResponse response = client.get(ROLES_ENDPOINT);
            response.assertStatusCode(HttpStatus.SC_OK);

            Map<String, Object> roles = response.bodyAsMap();
            assertThat("sample_full_access role should be present", roles, hasKey("sample_full_access"));
            assertThat("sample_read_access role should be present", roles, hasKey("sample_read_access"));
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testPluginDefaultRoleIsStaticAndReserved() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // Get a specific plugin-provided role
            TestRestClient.HttpResponse response = client.get(ROLES_ENDPOINT + "/sample_full_access");
            response.assertStatusCode(HttpStatus.SC_OK);

            Map<String, Object> body = response.bodyAsMap();
            Map<String, Object> role = (Map<String, Object>) body.get("sample_full_access");
            assertThat("Role should exist in response", role, is(notNullValue()));
            assertThat("Role should be static", role.get("static"), is(true));
            assertThat("Role should be reserved", role.get("reserved"), is(true));
        }
    }

    @Test
    public void testPluginDefaultRoleCannotBeModifiedByNonAdmin() {
        try (TestRestClient client = cluster.getRestClient(TestUtils.FULL_ACCESS_USER)) {
            // Attempt to delete a plugin-provided static role as non-admin — should be forbidden
            TestRestClient.HttpResponse response = client.delete(ROLES_ENDPOINT + "/sample_full_access");
            assertThat(
                "Deleting a static role should be forbidden for non-admin",
                response.getStatusCode(),
                equalTo(HttpStatus.SC_FORBIDDEN)
            );
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testPluginDefaultRoleHasCorrectPermissions() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse response = client.get(ROLES_ENDPOINT + "/sample_full_access");
            response.assertStatusCode(HttpStatus.SC_OK);

            Map<String, Object> body = response.bodyAsMap();
            Map<String, Object> role = (Map<String, Object>) body.get("sample_full_access");
            assertThat(role, is(notNullValue()));

            var clusterPerms = (java.util.List<String>) role.get("cluster_permissions");
            assertThat("Should have cluster permissions", clusterPerms, is(notNullValue()));
            assertThat(clusterPerms.contains("cluster:admin/sample-resource-plugin/*"), is(true));
        }
    }
}
