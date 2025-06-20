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
import org.apache.http.HttpStatus;
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
import static org.opensearch.security.auditlog.impl.AuditCategory.AUTHENTICATED;
import static org.opensearch.security.auditlog.impl.AuditCategory.FAILED_LOGIN;
import static org.opensearch.security.auditlog.impl.AuditCategory.GRANTED_PRIVILEGES;
import static org.opensearch.security.auditlog.impl.AuditCategory.MISSING_PRIVILEGES;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.privilegePredicateRESTLayer;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.privilegePredicateTransportLayer;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class AuthZinRestLayerTests {
    protected final static TestSecurityConfig.User REST_ONLY = new TestSecurityConfig.User("rest_only").roles(
        new Role("rest_only_role").clusterPermissions("security:dummy_protected/get").clusterPermissions("cluster:admin/dummy_plugin/dummy")
    );

    protected final static TestSecurityConfig.User TRANSPORT_ONLY = new TestSecurityConfig.User("transport_only").roles(
        new Role("transport_only_role").clusterPermissions("cluster:admin/dummy_plugin/dummy")
    );

    protected final static TestSecurityConfig.User REST_PLUS_TRANSPORT = new TestSecurityConfig.User("rest_plus_transport").roles(
        new Role("rest_plus_transport_role").clusterPermissions("security:dummy_protected/get")
            .clusterPermissions("cluster:admin/dummy_plugin/dummy", "cluster:admin/dummy_protected_plugin/dummy/get")
    );

    protected final static TestSecurityConfig.User NO_PERM = new TestSecurityConfig.User("no_perm").roles(new Role("no_perm_role"));

    protected final static TestSecurityConfig.User UNREGISTERED = new TestSecurityConfig.User("unregistered");

    public static final String UNPROTECTED_BASE_ENDPOINT = "_plugins/_dummy";
    public static final String PROTECTED_BASE_ENDPOINT = "_plugins/_dummy_protected";
    public static final String UNPROTECTED_API = UNPROTECTED_BASE_ENDPOINT + "/dummy";
    public static final String PROTECTED_API = PROTECTED_BASE_ENDPOINT + "/dummy";

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(REST_ONLY, REST_PLUS_TRANSPORT, TRANSPORT_ONLY, NO_PERM)
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
    public void testShouldNotAllowUnregisteredUsers() {
        try (TestRestClient client = cluster.getRestClient(UNREGISTERED)) {
            // Legacy plugin
            assertThat(client.get(UNPROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
            auditLogsRule.assertExactlyOne(privilegePredicateRESTLayer(FAILED_LOGIN, UNREGISTERED, GET, "/" + UNPROTECTED_API));

            // Protected Routes plugin
            assertThat(client.get(PROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
            auditLogsRule.assertExactlyOne(privilegePredicateRESTLayer(FAILED_LOGIN, UNREGISTERED, GET, "/" + PROTECTED_API));
        }
    }

    @Test
    public void testAccessDeniedForUserWithNoPermissions() {
        try (TestRestClient client = cluster.getRestClient(NO_PERM)) {
            // fail at Transport (won't have a rest authz success audit log since this is not a protected endpoint)
            assertThat(client.get(UNPROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
            auditLogsRule.assertExactlyScanAll(
                1,
                privilegePredicateTransportLayer(MISSING_PRIVILEGES, NO_PERM, "DummyRequest", "cluster:admin/dummy_plugin/dummy")
            );

            // fail at REST
            assertThat(client.get(PROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
            auditLogsRule.assertExactlyOne(privilegePredicateRESTLayer(MISSING_PRIVILEGES, NO_PERM, GET, "/" + PROTECTED_API));
        }
    }

    @Test
    public void testShouldFailWithoutPermForPathWithoutLeadingSlashes() {
        try (TestRestClient client = cluster.getRestClient(NO_PERM)) {

            // Protected Routes plugin
            assertThat(client.getWithoutLeadingSlash(PROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
        }
    }

    /** AuthZ in REST Layer check */

    @Test
    public void testShouldAllowAtRestAndBlockAtTransport() {
        try (TestRestClient client = cluster.getRestClient(REST_ONLY)) {
            assertThat(client.get(PROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
            // granted at Rest layer
            auditLogsRule.assertExactlyOne(privilegePredicateRESTLayer(GRANTED_PRIVILEGES, REST_ONLY, GET, "/" + PROTECTED_API));
            // missing at Transport layer
            auditLogsRule.assertExactlyScanAll(
                1,
                privilegePredicateTransportLayer(
                    MISSING_PRIVILEGES,
                    REST_ONLY,
                    "DummyRequest",
                    "cluster:admin/dummy_protected_plugin/dummy/get"
                )
            );
        }
    }

    @Test
    public void testRequestBodyIsAuditLogged() {
        try (TestRestClient client = cluster.getRestClient(REST_PLUS_TRANSPORT)) {
            String dummyBody = "{\"hello\": \"world\"}";
            client.postJson(PROTECTED_API, dummyBody);
            auditLogsRule.assertExactlyOne(
                privilegePredicateRESTLayer(AUTHENTICATED, REST_PLUS_TRANSPORT, POST, "/" + PROTECTED_API).withRequestBody(dummyBody)
            );
        }
    }

    @Test
    public void testShouldAllowAtRestAndTransport() {
        try (TestRestClient client = cluster.getRestClient(REST_PLUS_TRANSPORT)) {
            assertOKResponseFromProtectedPlugin(client);

            auditLogsRule.assertExactlyOne(privilegePredicateRESTLayer(GRANTED_PRIVILEGES, REST_PLUS_TRANSPORT, GET, "/" + PROTECTED_API));
            auditLogsRule.assertExactlyScanAll(
                1,
                privilegePredicateTransportLayer(
                    GRANTED_PRIVILEGES,
                    REST_PLUS_TRANSPORT,
                    "DummyRequest",
                    "cluster:admin/dummy_protected_plugin/dummy/get"
                )
            );
        }
    }

    @Test
    public void testShouldBlockAccessToEndpointForWhichUserHasNoPermission() {
        try (TestRestClient client = cluster.getRestClient(REST_ONLY)) {
            assertThat(client.post(PROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));

            auditLogsRule.assertExactlyOne(privilegePredicateRESTLayer(MISSING_PRIVILEGES, REST_ONLY, POST, "/" + PROTECTED_API));
        }

        try (TestRestClient client = cluster.getRestClient(REST_PLUS_TRANSPORT)) {
            assertThat(client.post(PROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));

            auditLogsRule.assertExactlyOne(privilegePredicateRESTLayer(MISSING_PRIVILEGES, REST_PLUS_TRANSPORT, POST, "/" + PROTECTED_API));
        }
    }

    /** Backwards compatibility check */

    @Test
    public void testBackwardsCompatibility() {

        // TRANSPORT_ONLY should have access to legacy endpoint, but not protected endpoint
        try (TestRestClient client = cluster.getRestClient(TRANSPORT_ONLY)) {
            TestRestClient.HttpResponse res = client.get(PROTECTED_API);
            assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
            auditLogsRule.assertExactlyOne(privilegePredicateRESTLayer(MISSING_PRIVILEGES, TRANSPORT_ONLY, GET, "/" + PROTECTED_API));

            assertOKResponseFromLegacyPlugin(client);
            // check that there is no log for REST layer AuthZ since this is an unprotected endpoint
            auditLogsRule.assertExactly(0, privilegePredicateRESTLayer(GRANTED_PRIVILEGES, TRANSPORT_ONLY, GET, UNPROTECTED_API));
            // check that there is exactly 1 message for Transport Layer privilege evaluation
            auditLogsRule.assertExactlyScanAll(
                1,
                privilegePredicateTransportLayer(GRANTED_PRIVILEGES, TRANSPORT_ONLY, "DummyRequest", "cluster:admin/dummy_plugin/dummy")
            );
        }

        // REST_ONLY should have access to legacy endpoint (protected endpoint already tested above)
        try (TestRestClient client = cluster.getRestClient(REST_ONLY)) {
            assertOKResponseFromLegacyPlugin(client);
            auditLogsRule.assertExactly(0, privilegePredicateRESTLayer(GRANTED_PRIVILEGES, REST_ONLY, GET, UNPROTECTED_API));
            auditLogsRule.assertExactlyScanAll(
                1,
                privilegePredicateTransportLayer(GRANTED_PRIVILEGES, REST_ONLY, "DummyRequest", "cluster:admin/dummy_plugin/dummy")
            );
        }

        // DUMMY_WITH_TRANSPORT_PERM should have access to legacy endpoint (protected endpoint already tested above)
        try (TestRestClient client = cluster.getRestClient(REST_PLUS_TRANSPORT)) {
            assertOKResponseFromLegacyPlugin(client);
            auditLogsRule.assertExactly(0, privilegePredicateRESTLayer(GRANTED_PRIVILEGES, REST_PLUS_TRANSPORT, GET, UNPROTECTED_API));
            auditLogsRule.assertExactlyScanAll(
                1,
                privilegePredicateTransportLayer(
                    GRANTED_PRIVILEGES,
                    REST_PLUS_TRANSPORT,
                    "DummyRequest",
                    "cluster:admin/dummy_plugin/dummy"
                )
            );
        }

        // NO_PERM should not have access to legacy endpoint (protected endpoint already tested above)
        try (TestRestClient client = cluster.getRestClient(NO_PERM)) {
            assertThat(client.get(UNPROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
            auditLogsRule.assertExactly(0, privilegePredicateRESTLayer(MISSING_PRIVILEGES, NO_PERM, GET, UNPROTECTED_API));
            auditLogsRule.assertExactlyScanAll(
                1,
                privilegePredicateTransportLayer(MISSING_PRIVILEGES, NO_PERM, "DummyRequest", "cluster:admin/dummy_plugin/dummy")
            );
        }

        // UNREGISTERED should not have access to legacy endpoint (protected endpoint already tested above)
        try (TestRestClient client = cluster.getRestClient(UNREGISTERED)) {
            assertThat(client.get(UNPROTECTED_API).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
            auditLogsRule.assertExactly(0, privilegePredicateRESTLayer(MISSING_PRIVILEGES, UNREGISTERED, GET, UNPROTECTED_API));
            auditLogsRule.assertExactly(
                0,
                privilegePredicateTransportLayer(MISSING_PRIVILEGES, UNREGISTERED, "DummyRequest", "cluster:admin/dummy_plugin/dummy")
            );
            auditLogsRule.assertExactly(0, privilegePredicateRESTLayer(FAILED_LOGIN, UNREGISTERED, GET, UNPROTECTED_API));
        }
    }

    /** Helper Methods */
    private void assertOKResponseFromLegacyPlugin(TestRestClient client) {
        String expectedResponseFromLegacyPlugin = "{\"response_string\":\"Hello from dummy plugin\"}";
        TestRestClient.HttpResponse res = client.get(UNPROTECTED_API);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(res.getBody(), equalTo(expectedResponseFromLegacyPlugin));
    }

    private void assertOKResponseFromProtectedPlugin(TestRestClient client) {
        String expectedResponseFromProtectedPlugin = "{\"response_string\":\"Hello from dummy protected plugin\"}";
        TestRestClient.HttpResponse res = client.get(PROTECTED_API);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(res.getBody(), equalTo(expectedResponseFromProtectedPlugin));
    }
}
