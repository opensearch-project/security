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
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.test.framework.AuditCompliance;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThan;
import static org.opensearch.security.auditlog.impl.AuditCategory.GRANTED_PRIVILEGES;
import static org.opensearch.security.auditlog.impl.AuditCategory.MISSING_PRIVILEGES;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.auditPredicate;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.grantedPrivilege;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.userAuthenticated;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class WhoAmITests {
    protected final static TestSecurityConfig.User WHO_AM_I = new TestSecurityConfig.User("who_am_i_user").roles(
        new Role("who_am_i_role").clusterPermissions("security:whoamiprotected")
    );

    protected final static TestSecurityConfig.User AUDIT_LOG_VERIFIER = new TestSecurityConfig.User("audit_log_verifier").roles(
        new Role("audit_log_verifier_role").clusterPermissions("*").indexPermissions("*").on("*")
    );

    protected final static TestSecurityConfig.User WHO_AM_I_LEGACY = new TestSecurityConfig.User("who_am_i_user_legacy").roles(
        new Role("who_am_i_role_legacy").clusterPermissions("cluster:admin/opendistro_security/whoamiprotected")
    );

    protected final static TestSecurityConfig.User WHO_AM_I_NO_PERM = new TestSecurityConfig.User("who_am_i_user_no_perm").roles(
        new Role("who_am_i_role_no_perm")
    );

    protected final static TestSecurityConfig.User WHO_AM_I_UNREGISTERED = new TestSecurityConfig.User("who_am_i_user_no_perm");

    protected final String expectedAuthorizedBody = "{\"dn\":null,\"is_admin\":false,\"is_node_certificate_request\":false}";
    protected final String expectedUnuauthorizedBody =
        "no permissions for [security:whoamiprotected] and User [name=who_am_i_user_no_perm, backend_roles=[], requestedTenant=null]";

    public static final String WHOAMI_ENDPOINT = "_plugins/_security/whoami";
    public static final String WHOAMI_PROTECTED_ENDPOINT = "_plugins/_security/whoamiprotected";

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(WHO_AM_I, WHO_AM_I_LEGACY, WHO_AM_I_NO_PERM, AUDIT_LOG_VERIFIER)
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
            assertResponse(client.get(WHOAMI_PROTECTED_ENDPOINT), HttpStatus.SC_OK, expectedAuthorizedBody);

            // audit log, named route
            assertExactlyOneAuthenticatedLogMessage(WHO_AM_I);
            assertExactlyOnePrivilegeEvaluationMessage(GRANTED_PRIVILEGES, WHO_AM_I);

            assertResponse(client.get(WHOAMI_ENDPOINT), HttpStatus.SC_OK, expectedAuthorizedBody);
        }
    }

    @Test
    public void testWhoAmIWithGetPermissionsLegacy() {
        try (TestRestClient client = cluster.getRestClient(WHO_AM_I_LEGACY)) {
            assertResponse(client.get(WHOAMI_PROTECTED_ENDPOINT), HttpStatus.SC_OK, expectedAuthorizedBody);

            // audit log, named route
            assertExactlyOneAuthenticatedLogMessage(WHO_AM_I_LEGACY);
            assertExactlyOnePrivilegeEvaluationMessage(GRANTED_PRIVILEGES, WHO_AM_I_LEGACY);

            assertResponse(client.get(WHOAMI_ENDPOINT), HttpStatus.SC_OK, expectedAuthorizedBody);
        }
    }

    @Test
    public void testWhoAmIWithoutGetPermissions() {
        try (TestRestClient client = cluster.getRestClient(WHO_AM_I_NO_PERM)) {
            assertResponse(client.get(WHOAMI_PROTECTED_ENDPOINT), HttpStatus.SC_UNAUTHORIZED, expectedUnuauthorizedBody);
            // audit log, named route
            assertExactlyOneAuthenticatedLogMessage(WHO_AM_I_NO_PERM);
            assertExactlyOnePrivilegeEvaluationMessage(MISSING_PRIVILEGES, WHO_AM_I_NO_PERM);

            assertResponse(client.get(WHOAMI_ENDPOINT), HttpStatus.SC_OK, expectedAuthorizedBody);
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

    @Test
    public void testAuditLogSimilarityWithTransportLayer() {
        try (TestRestClient client = cluster.getRestClient(AUDIT_LOG_VERIFIER)) {
            assertResponse(client.get(WHOAMI_PROTECTED_ENDPOINT), HttpStatus.SC_OK, expectedAuthorizedBody);
            assertExactlyOnePrivilegeEvaluationMessage(GRANTED_PRIVILEGES, AUDIT_LOG_VERIFIER);

            assertThat(client.get("_cat/indices").getStatusCode(), equalTo(HttpStatus.SC_OK));

            // transport layer audit messages
            auditLogsRule.assertExactly(2, grantedPrivilege(AUDIT_LOG_VERIFIER, "GetSettingsRequest"));

            List<AuditMessage> grantedPrivilegesMessages = auditLogsRule.getCurrentTestAuditMessages()
                .stream()
                .filter(msg -> msg.getCategory().equals(GRANTED_PRIVILEGES))
                .collect(Collectors.toList());

            verifyAuditLogSimilarity(grantedPrivilegesMessages);
        }
    }

    private void assertResponse(TestRestClient.HttpResponse response, int expectedStatus, String expectedBody) {
        assertThat(response.getStatusCode(), equalTo(expectedStatus));
        assertThat(response.getBody(), equalTo(expectedBody));
    }

    private void assertExactlyOneAuthenticatedLogMessage(TestSecurityConfig.User user) {
        auditLogsRule.assertExactly(
            1,
            userAuthenticated(user).withLayer(AuditLog.Origin.REST)
                .withRestMethod(RestRequest.Method.GET)
                .withRequestPath("/" + WhoAmITests.WHOAMI_PROTECTED_ENDPOINT)
                .withInitiatingUser(user)
        );
    }

    private void assertExactlyOnePrivilegeEvaluationMessage(AuditCategory privileges, TestSecurityConfig.User user) {
        auditLogsRule.assertExactly(
            1,
            auditPredicate(privileges).withLayer(AuditLog.Origin.REST)
                .withRestMethod(RestRequest.Method.GET)
                .withRequestPath("/" + WhoAmITests.WHOAMI_PROTECTED_ENDPOINT)
                .withEffectiveUser(user)
        );
    }

    private void verifyAuditLogSimilarity(List<AuditMessage> currentTestAuditMessages) {
        List<AuditMessage> restSet = new ArrayList<>();
        List<AuditMessage> transportSet = new ArrayList<>();

        // It is okay to loop through all even though we end up using only 2, as the total number of messages should be around 8
        for (AuditMessage auditMessage : currentTestAuditMessages) {
            if ("REST".equals(auditMessage.getAsMap().get(AuditMessage.REQUEST_LAYER).toString())) {
                restSet.add(auditMessage);
            } else if ("TRANSPORT".equals(auditMessage.getAsMap().get(AuditMessage.REQUEST_LAYER).toString())) {
                transportSet.add(auditMessage);
            }
        }
        // We pass 1 message from each layer to check for similarity
        checkForStructuralSimilarity(restSet.get(0), transportSet.get(0));
    }

    /**
     * Checks for structural similarity between audit message generated at Rest layer vs transport layer
     * Example REST audit message for GRANTED_PRIVILEGES:
     * {
     *    "audit_cluster_name":"local_cluster_1",
     *    "audit_node_name":"data_0",
     *    "audit_rest_request_method":"GET",
     *    "audit_category":"GRANTED_PRIVILEGES",
     *    "audit_request_origin":"REST",
     *    "audit_node_id":"Dez5cwAAQAC6cdmK_____w",
     *    "audit_request_layer":"REST",
     *    "audit_rest_request_path":"/_plugins/_security/whoamiprotected",
     *    "@timestamp":"2023-08-16T17:35:53.531+00:00",
     *    "audit_format_version":4,
     *    "audit_request_remote_address":"127.0.0.1",
     *    "audit_node_host_address":"127.0.0.1",
     *    "audit_rest_request_headers":{
     *       "Connection":[
     *          "keep-alive"
     *       ],
     *       "User-Agent":[
     *          "Apache-HttpClient/5.2.1 (Java/19.0.1)"
     *       ],
     *       "content-length":[
     *          "0"
     *       ],
     *       "Host":[
     *          "127.0.0.1:47210"
     *       ],
     *       "Accept-Encoding":[
     *          "gzip, x-gzip, deflate"
     *       ]
     *    },
     *    "audit_request_effective_user":"audit_log_verifier",
     *    "audit_node_host_name":"127.0.0.1"
     * }
     *
     *
     * Example Transport audit message for GRANTED_PRIVILEGES:
     * {
     *    "audit_cluster_name":"local_cluster_1",
     *    "audit_transport_headers":{
     *       "_system_index_access_allowed":"false"
     *    },
     *    "audit_node_name":"data_0",
     *    "audit_trace_task_id":"Dez5cwAAQAC6cdmK_____w:87",
     *    "audit_transport_request_type":"GetSettingsRequest",
     *    "audit_category":"GRANTED_PRIVILEGES",
     *    "audit_request_origin":"REST",
     *    "audit_node_id":"Dez5cwAAQAC6cdmK_____w",
     *    "audit_request_layer":"TRANSPORT",
     *    "@timestamp":"2023-08-16T17:35:53.621+00:00",
     *    "audit_format_version":4,
     *    "audit_request_remote_address":"127.0.0.1",
     *    "audit_request_privilege":"indices:monitor/settings/get",
     *    "audit_node_host_address":"127.0.0.1",
     *    "audit_request_effective_user":"audit_log_verifier",
     *    "audit_node_host_name":"127.0.0.1"
     * }
     *
     *
     * @param restAuditMessage audit message generated at REST layer
     * @param transportAuditMessage audit message generated at Transport layer
     */
    private void checkForStructuralSimilarity(AuditMessage restAuditMessage, AuditMessage transportAuditMessage) {

        Set<String> restAuditSet = restAuditMessage.getAsMap().keySet();
        Set<String> transportAuditSet = transportAuditMessage.getAsMap().keySet();

        // Added a magic number here and below, because there are always 15 or more items in each message generated via Audit logs
        assertThat(restAuditSet.size(), greaterThan(14));
        assertThat(transportAuditSet.size(), greaterThan(14));

        restAuditSet.removeAll(transportAuditMessage.getAsMap().keySet());
        transportAuditSet.removeAll(restAuditMessage.getAsMap().keySet());

        // We compare two sets and see there were more than 10 items with same keys indicating these logs are similar
        // There are a few headers that are generated different for REST vs TRANSPORT layer audit logs, but that is expected
        // The end goal of this test is to ensure similarity, not equality.
        assertThat(restAuditSet.size(), lessThan(5));
        assertThat(transportAuditSet.size(), lessThan(5));
    }
}
