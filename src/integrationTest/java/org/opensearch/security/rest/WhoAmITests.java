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
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.test.framework.AuditCompliance;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.auditlog.impl.AuditCategory.GRANTED_PRIVILEGES;
import static org.opensearch.security.auditlog.impl.AuditCategory.MISSING_PRIVILEGES;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.auditPredicate;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.userAuthenticated;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class WhoAmITests {
    protected final static TestSecurityConfig.User WHO_AM_I = new TestSecurityConfig.User("who_am_i_user").roles(
        new Role("who_am_i_role").clusterPermissions("security:whoamiprotected")
    );

    protected final static TestSecurityConfig.User WHO_AM_I_LEGACY = new TestSecurityConfig.User("who_am_i_user_legacy").roles(
        new Role("who_am_i_role_legacy").clusterPermissions("cluster:admin/opendistro_security/whoamiprotected")
    );

    protected final static TestSecurityConfig.User WHO_AM_I_NO_PERM = new TestSecurityConfig.User("who_am_i_user_no_perm").roles(
        new Role("who_am_i_role_no_perm")
    );

    protected final static TestSecurityConfig.User WHO_AM_I_UNREGISTERED = new TestSecurityConfig.User("who_am_i_user_no_perm");

    public static final String WHOAMI_ENDPOINT = "_plugins/_security/whoami";
    public static final String WHOAMI_PROTECTED_ENDPOINT = "_plugins/_security/whoamiprotected";

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(WHO_AM_I, WHO_AM_I_LEGACY, WHO_AM_I_NO_PERM)
        .audit(
            new AuditConfiguration(true).compliance(new AuditCompliance().enabled(true))
                .filters(new AuditFilters().enabledRest(true).enabledTransport(true).resolveBulkRequests(true))
        )
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void testWhoAmIWithGetPermissions() {
        try (TestRestClient client = cluster.getRestClient(WHO_AM_I)) {
            assertThat(client.get(WHOAMI_PROTECTED_ENDPOINT).getStatusCode(), equalTo(HttpStatus.SC_OK));

            // audit log, named route
            auditLogsRule.assertExactly(
                1,
                userAuthenticated(WHO_AM_I).withLayer(AuditLog.Origin.REST)
                    .withRestMethod(RestRequest.Method.GET)
                    .withRequestPath("/" + WHOAMI_PROTECTED_ENDPOINT)
                    .withInitiatingUser(WHO_AM_I)
            );
            auditLogsRule.assertExactly(
                1,
                auditPredicate(GRANTED_PRIVILEGES).withLayer(AuditLog.Origin.REST)
                    .withRestMethod(RestRequest.Method.GET)
                    .withRequestPath("/" + WHOAMI_PROTECTED_ENDPOINT)
                    .withEffectiveUser(WHO_AM_I)
            );
        }

        try (TestRestClient client = cluster.getRestClient(WHO_AM_I)) {
            assertThat(client.get(WHOAMI_ENDPOINT).getStatusCode(), equalTo(HttpStatus.SC_OK));
        }
    }

    @Test
    public void testWhoAmIWithGetPermissionsLegacy() {
        try (TestRestClient client = cluster.getRestClient(WHO_AM_I_LEGACY)) {
            assertThat(client.get(WHOAMI_ENDPOINT).getStatusCode(), equalTo(HttpStatus.SC_OK));
        }

        try (TestRestClient client = cluster.getRestClient(WHO_AM_I_LEGACY)) {
            assertThat(client.get(WHOAMI_PROTECTED_ENDPOINT).getStatusCode(), equalTo(HttpStatus.SC_OK));

            // audit log, named route
            auditLogsRule.assertExactly(
                1,
                userAuthenticated(WHO_AM_I_LEGACY).withLayer(AuditLog.Origin.REST)
                    .withRestMethod(RestRequest.Method.GET)
                    .withRequestPath("/" + WHOAMI_PROTECTED_ENDPOINT)
                    .withInitiatingUser(WHO_AM_I_LEGACY)
            );
            auditLogsRule.assertExactly(
                1,
                auditPredicate(GRANTED_PRIVILEGES).withLayer(AuditLog.Origin.REST)
                    .withRestMethod(RestRequest.Method.GET)
                    .withRequestPath("/" + WHOAMI_PROTECTED_ENDPOINT)
                    .withEffectiveUser(WHO_AM_I_LEGACY)
            );
        }
    }

    @Test
    public void testWhoAmIWithoutGetPermissions() {
        try (TestRestClient client = cluster.getRestClient(WHO_AM_I_NO_PERM)) {
            assertThat(client.get(WHOAMI_ENDPOINT).getStatusCode(), equalTo(HttpStatus.SC_OK));
        }

        try (TestRestClient client = cluster.getRestClient(WHO_AM_I_NO_PERM)) {
            assertThat(client.get(WHOAMI_PROTECTED_ENDPOINT).getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));

            // audit log, named route
            auditLogsRule.assertExactly(
                1,
                userAuthenticated(WHO_AM_I_NO_PERM).withLayer(AuditLog.Origin.REST)
                    .withRestMethod(RestRequest.Method.GET)
                    .withRequestPath("/" + WHOAMI_PROTECTED_ENDPOINT)
            );
            auditLogsRule.assertExactly(
                1,
                auditPredicate(MISSING_PRIVILEGES).withLayer(AuditLog.Origin.REST)
                    .withRestMethod(RestRequest.Method.GET)
                    .withRequestPath("/" + WHOAMI_PROTECTED_ENDPOINT)
                    .withEffectiveUser(WHO_AM_I_NO_PERM)
            );
        }
    }

    @Test
    public void testWhoAmIPost() {
        try (TestRestClient client = cluster.getRestClient(WHO_AM_I)) {
            assertThat(client.post(WHOAMI_ENDPOINT).getStatusCode(), equalTo(HttpStatus.SC_OK));
        }

        try (TestRestClient client = cluster.getRestClient(WHO_AM_I_LEGACY)) {
            assertThat(client.post(WHOAMI_ENDPOINT).getStatusCode(), equalTo(HttpStatus.SC_OK));
        }

        try (TestRestClient client = cluster.getRestClient(WHO_AM_I_NO_PERM)) {
            assertThat(client.post(WHOAMI_ENDPOINT).getStatusCode(), equalTo(HttpStatus.SC_OK));
        }

        try (TestRestClient client = cluster.getRestClient(WHO_AM_I_UNREGISTERED)) {
            assertThat(client.post(WHOAMI_ENDPOINT).getStatusCode(), equalTo(HttpStatus.SC_OK));
        }

    }
}
