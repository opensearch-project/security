/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.rest;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.test.framework.AuditCompliance;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.testplugins.dummy.CustomLegacyTestPlugin;
import org.opensearch.test.framework.testplugins.dummyprotected.CustomRestProtectedTestPlugin;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class AuthZinRestLayerTests {
    protected final static TestSecurityConfig.User DUMMY_REST_ONLY = new TestSecurityConfig.User("dummy_rest_only").roles(
        new Role("dummy_rest_only_role").clusterPermissions("security:dummy_protected/get")
            .clusterPermissions("cluster:admin/dummy_plugin/dummy")
    );

    protected final static TestSecurityConfig.User DUMMY_WITH_TRANSPORT_PERM = new TestSecurityConfig.User("dummy_transport_perm").roles(
        new Role("dummy_transport_perm_role").clusterPermissions("security:dummy_protected/get")
            .clusterPermissions("cluster:admin/dummy_plugin/dummy", "cluster:admin/dummy_protected_plugin/dummy")
    );

    protected final static TestSecurityConfig.User DUMMY_LEGACY = new TestSecurityConfig.User("dummy_user_legacy").roles(
        new Role("dummy_role_legacy").clusterPermissions("cluster:admin/dummy_plugin/dummy")
    );

    protected final static TestSecurityConfig.User DUMMY_NO_PERM = new TestSecurityConfig.User("dummy_user_no_perm").roles(
        new Role("dummy_role_no_perm")
    );

    protected final static TestSecurityConfig.User DUMMY_UNREGISTERED = new TestSecurityConfig.User("dummy_user_not_registered");

    public static final String DUMMY_BASE_ENDPOINT = "_plugins/_dummy";
    public static final String DUMMY_PROTECTED_BASE_ENDPOINT = "_plugins/_dummy";
    public static final String DUMMY_API = DUMMY_BASE_ENDPOINT + "/dummy";
    public static final String DUMMY_PROTECTED_API = DUMMY_PROTECTED_BASE_ENDPOINT + "/dummy";

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(DUMMY_REST_ONLY, DUMMY_WITH_TRANSPORT_PERM, DUMMY_LEGACY, DUMMY_NO_PERM)
        .plugin(CustomLegacyTestPlugin.class)
        .plugin(CustomRestProtectedTestPlugin.class)
        .audit(
            new AuditConfiguration(true).compliance(new AuditCompliance().enabled(true))
                .filters(new AuditFilters().enabledRest(true).enabledTransport(true).resolveBulkRequests(true))
        )
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    // Class-level TODO: Ensure all tests have checks for status, body and audit logs (as needed)

    /* Basic Access check */

    @Test
    public void testShouldFailForUnregisteredUsers() {
        try (TestRestClient client = cluster.getRestClient(DUMMY_UNREGISTERED)) {
            assertThat(client.get(DUMMY_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
            assertThat(client.get(DUMMY_PROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
        }
    }

    @Test
    public void testShouldFailForBothPlugins() {
        try (TestRestClient client = cluster.getRestClient(DUMMY_NO_PERM)) {
            // fail at Transport
            assertThat(client.get(DUMMY_API).getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));

            // fail at REST
            assertThat(client.get(DUMMY_PROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));

            // TODO: add audit log check for both cases
        }
    }

    /* AuthZ in REST check */
    @Test
    public void testShouldFailAtTransportLayerWithRestOnlyPermission() {
        try (TestRestClient client = cluster.getRestClient(DUMMY_REST_ONLY)) {
            assertThat(client.get(DUMMY_PROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
            // TODO: add audit log check to verify it passes at REST layer and fails at Transport Layer
        }
    }

    @Test
    public void testShouldPassWithRequiredPermissions() {
        String expectedResponse = "{\"response_string\":\"Hello from dummy protected plugin\"}";
        try (TestRestClient client = cluster.getRestClient(DUMMY_WITH_TRANSPORT_PERM)) {
            TestRestClient.HttpResponse res = client.get(DUMMY_PROTECTED_API);
            assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));
            assertThat(res.getBody(), equalTo(expectedResponse));
            // TODO: add audit log check to verify it passes at REST layer and at Transport Layer
        }
    }

    // TODO: Add test that verifies failed execution with DUMMY_REST_ONLY & DUMMY_WITH_TRANSPORT for POST request, both should fail at REST
    // layer

    /* Backwards compatibility check */
    // TODO: add a test that verifies that DUMMY_LEGACY cannot access the protected endpoint from new plugin but can still endpoints from
    // legacy plugin with only transport permission, also add audit log check

    // TODO: add a test to verify that DUMMY_REST_ONLY & DUMMY_WITH_TRANSPORT can access legacy plugin endpoints with only transport
    // permissions

}
