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
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.auditlog.impl.AuditCategory.FAILED_LOGIN;
import static org.opensearch.security.auditlog.impl.AuditCategory.GRANTED_PRIVILEGES;
import static org.opensearch.security.auditlog.impl.AuditCategory.MISSING_PRIVILEGES;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.privilegePredicateRESTLayer;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.privilegePredicateTransportLayer;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class AuthZinRestLayerTests {
    protected final static TestSecurityConfig.User DUMMY_REST_ONLY = new TestSecurityConfig.User("dummy_rest_only").roles(
        new Role("dummy_rest_only_role").clusterPermissions("security:dummy_protected/get")
            .clusterPermissions("cluster:admin/dummy_plugin/dummy")
    );

    protected final static TestSecurityConfig.User DUMMY_WITH_TRANSPORT_PERM = new TestSecurityConfig.User("dummy_transport_perm").roles(
        new Role("dummy_transport_perm_role").clusterPermissions("security:dummy_protected/get")
            .clusterPermissions("cluster:admin/dummy_plugin/dummy", "cluster:admin/dummy_protected_plugin/dummy/get")
    );

    protected final static TestSecurityConfig.User DUMMY_LEGACY = new TestSecurityConfig.User("dummy_user_legacy").roles(
        new Role("dummy_role_legacy").clusterPermissions("cluster:admin/dummy_plugin/dummy")
    );

    protected final static TestSecurityConfig.User DUMMY_NO_PERM = new TestSecurityConfig.User("dummy_user_no_perm").roles(
        new Role("dummy_role_no_perm")
    );

    protected final static TestSecurityConfig.User DUMMY_UNREGISTERED = new TestSecurityConfig.User("dummy_user_not_registered");

    public static final String DUMMY_BASE_ENDPOINT = "_plugins/_dummy";
    public static final String DUMMY_PROTECTED_BASE_ENDPOINT = "_plugins/_dummy_protected";
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

    /** Basic Access check */

    @Test
    public void testShouldFailForUnregisteredUsers() {
        try (TestRestClient client = cluster.getRestClient(DUMMY_UNREGISTERED)) {
            // Legacy plugin
            assertThat(client.get(DUMMY_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
            auditLogsRule.assertExactlyOne(privilegePredicateRESTLayer(FAILED_LOGIN, DUMMY_UNREGISTERED, GET, "/" + DUMMY_API));

            // Protected Routes plugin
            assertThat(client.get(DUMMY_PROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
            auditLogsRule.assertExactlyOne(privilegePredicateRESTLayer(FAILED_LOGIN, DUMMY_UNREGISTERED, GET, "/" + DUMMY_PROTECTED_API));
        }
    }

    @Test
    public void testShouldFailForBothPlugins() {
        try (TestRestClient client = cluster.getRestClient(DUMMY_NO_PERM)) {
            // fail at Transport
            assertThat(client.get(DUMMY_API).getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
            auditLogsRule.assertExactlyOne(
                privilegePredicateTransportLayer(MISSING_PRIVILEGES, DUMMY_NO_PERM, "DummyRequest", "cluster:admin/dummy_plugin/dummy")
            );

            // fail at REST
            assertThat(client.get(DUMMY_PROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
            auditLogsRule.assertExactlyOne(privilegePredicateRESTLayer(MISSING_PRIVILEGES, DUMMY_NO_PERM, GET, "/" + DUMMY_PROTECTED_API));
        }
    }

    /** AuthZ in REST Layer check */

    @Test
    public void testShouldFailAtTransportLayerWithRestOnlyPermission() {
        try (TestRestClient client = cluster.getRestClient(DUMMY_REST_ONLY)) {
            assertThat(client.get(DUMMY_PROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
            // granted at Rest layer
            auditLogsRule.assertExactlyOne(
                privilegePredicateRESTLayer(GRANTED_PRIVILEGES, DUMMY_REST_ONLY, GET, "/" + DUMMY_PROTECTED_API)
            );
            // missing at Transport layer
            auditLogsRule.assertExactlyOne(
                privilegePredicateTransportLayer(
                    MISSING_PRIVILEGES,
                    DUMMY_REST_ONLY,
                    "DummyRequest",
                    "cluster:admin/dummy_protected_plugin/dummy/get"
                )
            );
        }
    }

    @Test
    public void testShouldPassWithRequiredPermissions() {
        try (TestRestClient client = cluster.getRestClient(DUMMY_WITH_TRANSPORT_PERM)) {
            assertOKResponseFromProtectedPlugin(client);

            auditLogsRule.assertExactlyOne(
                privilegePredicateRESTLayer(GRANTED_PRIVILEGES, DUMMY_WITH_TRANSPORT_PERM, GET, "/" + DUMMY_PROTECTED_API)
            );
            auditLogsRule.assertExactlyOne(
                privilegePredicateTransportLayer(
                    GRANTED_PRIVILEGES,
                    DUMMY_WITH_TRANSPORT_PERM,
                    "DummyRequest",
                    "cluster:admin/dummy_protected_plugin/dummy/get"
                )
            );
        }
    }

    @Test
    public void testShouldFailForPOST() {
        try (TestRestClient client = cluster.getRestClient(DUMMY_REST_ONLY)) {
            assertThat(client.post(DUMMY_PROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));

            auditLogsRule.assertExactlyOne(
                privilegePredicateRESTLayer(MISSING_PRIVILEGES, DUMMY_REST_ONLY, POST, "/" + DUMMY_PROTECTED_API)
            );
        }

        try (TestRestClient client = cluster.getRestClient(DUMMY_WITH_TRANSPORT_PERM)) {
            assertThat(client.post(DUMMY_PROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));

            auditLogsRule.assertExactlyOne(
                privilegePredicateRESTLayer(MISSING_PRIVILEGES, DUMMY_WITH_TRANSPORT_PERM, POST, "/" + DUMMY_PROTECTED_API)
            );
        }
    }

    /** Backwards compatibility check */

    @Test
    public void testBackwardsCompatibility() {

        // DUMMY_LEGACY should have access to legacy endpoint, but not protected endpoint
        try (TestRestClient client = cluster.getRestClient(DUMMY_LEGACY)) {
            TestRestClient.HttpResponse res = client.get(DUMMY_PROTECTED_API);
            assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
            auditLogsRule.assertExactlyOne(privilegePredicateRESTLayer(MISSING_PRIVILEGES, DUMMY_LEGACY, GET, "/" + DUMMY_PROTECTED_API));

            assertOKResponseFromLegacyPlugin(client);
            // check that there is no log for REST layer AuthZ since this is an unprotected endpoint
            auditLogsRule.assertExactly(0, privilegePredicateRESTLayer(GRANTED_PRIVILEGES, DUMMY_LEGACY, GET, DUMMY_API));
            // check that there is exactly 1 message for Transport Layer privilege evaluation
            auditLogsRule.assertExactlyOne(
                privilegePredicateTransportLayer(GRANTED_PRIVILEGES, DUMMY_LEGACY, "DummyRequest", "cluster:admin/dummy_plugin/dummy")
            );
        }

        // DUMMY_REST_ONLY should have access to legacy endpoint (protected endpoint already tested above)
        try (TestRestClient client = cluster.getRestClient(DUMMY_REST_ONLY)) {
            assertOKResponseFromLegacyPlugin(client);
            auditLogsRule.assertExactly(0, privilegePredicateRESTLayer(GRANTED_PRIVILEGES, DUMMY_REST_ONLY, GET, DUMMY_API));
            auditLogsRule.assertExactlyOne(
                privilegePredicateTransportLayer(GRANTED_PRIVILEGES, DUMMY_REST_ONLY, "DummyRequest", "cluster:admin/dummy_plugin/dummy")
            );
        }

        // DUMMY_WITH_TRANSPORT_PERM should have access to legacy endpoint (protected endpoint already tested above)
        try (TestRestClient client = cluster.getRestClient(DUMMY_WITH_TRANSPORT_PERM)) {
            assertOKResponseFromLegacyPlugin(client);
            auditLogsRule.assertExactly(0, privilegePredicateRESTLayer(GRANTED_PRIVILEGES, DUMMY_WITH_TRANSPORT_PERM, GET, DUMMY_API));
            auditLogsRule.assertExactlyOne(
                privilegePredicateTransportLayer(
                    GRANTED_PRIVILEGES,
                    DUMMY_WITH_TRANSPORT_PERM,
                    "DummyRequest",
                    "cluster:admin/dummy_plugin/dummy"
                )
            );
        }

        // DUMMY_NO_PERM should not have access to legacy endpoint (protected endpoint already tested above)
        try (TestRestClient client = cluster.getRestClient(DUMMY_NO_PERM)) {
            assertThat(client.get(DUMMY_API).getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
            auditLogsRule.assertExactly(0, privilegePredicateRESTLayer(MISSING_PRIVILEGES, DUMMY_NO_PERM, GET, DUMMY_API));
            auditLogsRule.assertExactlyOne(
                privilegePredicateTransportLayer(MISSING_PRIVILEGES, DUMMY_NO_PERM, "DummyRequest", "cluster:admin/dummy_plugin/dummy")
            );
        }

        // DUMMY_UNREGISTERED should not have access to legacy endpoint (protected endpoint already tested above)
        try (TestRestClient client = cluster.getRestClient(DUMMY_UNREGISTERED)) {
            assertThat(client.get(DUMMY_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
            auditLogsRule.assertExactly(0, privilegePredicateRESTLayer(MISSING_PRIVILEGES, DUMMY_UNREGISTERED, GET, DUMMY_API));
            auditLogsRule.assertExactly(
                0,
                privilegePredicateTransportLayer(MISSING_PRIVILEGES, DUMMY_UNREGISTERED, "DummyRequest", "cluster:admin/dummy_plugin/dummy")
            );
            auditLogsRule.assertExactly(0, privilegePredicateRESTLayer(FAILED_LOGIN, DUMMY_UNREGISTERED, GET, DUMMY_API));
        }
    }

    /** Helper Methods */
    private void assertOKResponseFromLegacyPlugin(TestRestClient client) {
        String expectedResponseFromLegacyPlugin = "{\"response_string\":\"Hello from dummy plugin\"}";
        TestRestClient.HttpResponse res = client.get(DUMMY_API);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(res.getBody(), equalTo(expectedResponseFromLegacyPlugin));
    }

    private void assertOKResponseFromProtectedPlugin(TestRestClient client) {
        String expectedResponseFromProtectedPlugin = "{\"response_string\":\"Hello from dummy protected plugin\"}";
        TestRestClient.HttpResponse res = client.get(DUMMY_PROTECTED_API);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(res.getBody(), equalTo(expectedResponseFromProtectedPlugin));
    }
}
