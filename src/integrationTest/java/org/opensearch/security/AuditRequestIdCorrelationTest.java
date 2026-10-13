/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.test.framework.AuditCompliance;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Integration tests for the audit_request_id correlation field.
 * Verifies that all audit events from a single REST request share the same
 * request ID, and that different requests produce different IDs.
 */
public class AuditRequestIdCorrelationTest {

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN)
        .audit(
            new AuditConfiguration(true).compliance(
                new AuditCompliance().enabled(true).writeWatchedIndices(List.of("watched-*")).writeLogDiffs(true)
            ).filters(new AuditFilters().enabledRest(true).enabledTransport(true))
        )
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void shouldCorrelateMultipleEventsFromSameRequest() throws Exception {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.putJson("correlation-test/_doc/1", "{\"field\":\"value\"}");
        }

        auditLogsRule.waitForAuditLogs();
        List<AuditMessage> messages = auditLogsRule.getCurrentTestAuditMessages();

        // Should produce multiple events (AUTHENTICATED + GRANTED_PRIVILEGES at minimum)
        assertThat(messages.size(), greaterThanOrEqualTo(2));

        // All events should have the same audit_request_id
        Set<Object> requestIds = messages.stream().map(msg -> msg.getAsMap().get(AuditMessage.REQUEST_ID)).collect(Collectors.toSet());

        // All non-null and all the same
        assertThat("All events should have a request ID", requestIds.stream().allMatch(id -> id != null), equalTo(true));
        assertThat("All events from same request should share one ID", requestIds.size(), equalTo(1));
    }

    @Test
    public void shouldUseClientProvidedXRequestIdHeader() throws Exception {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.putJson("header-id-test/_doc/1", "{\"data\":\"test\"}", new BasicHeader("X-Request-Id", "custom-trace-id-abc123"));
        }

        auditLogsRule.waitForAuditLogs();
        List<AuditMessage> messages = auditLogsRule.getCurrentTestAuditMessages();

        assertThat(messages.size(), greaterThanOrEqualTo(1));

        // All events should use the client-provided ID
        for (AuditMessage msg : messages) {
            assertThat(msg.getAsMap().get(AuditMessage.REQUEST_ID), equalTo("custom-trace-id-abc123"));
        }
    }

    @Test
    public void shouldGenerateIdWhenNoXRequestIdHeader() throws Exception {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.get("_cluster/health");
        }

        auditLogsRule.waitForAuditLogs();
        List<AuditMessage> messages = auditLogsRule.getCurrentTestAuditMessages();

        assertThat(messages.size(), greaterThanOrEqualTo(1));

        // Should have a generated ID (UUIDs.base64UUID() — ~20 chars, base64-encoded)
        String requestId = (String) messages.get(0).getAsMap().get(AuditMessage.REQUEST_ID);
        assertThat(requestId, notNullValue());
        assertThat("Generated ID should be non-empty", requestId.length(), greaterThanOrEqualTo(1));
    }

    @Test
    public void shouldProduceDifferentIdsForDifferentRequests() throws Exception {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.get("_cluster/health");
            client.get("_cluster/health");
        }
        auditLogsRule.waitForAuditLogs();
        List<AuditMessage> messages = auditLogsRule.getCurrentTestAuditMessages();

        // Collect all distinct request IDs
        Set<Object> requestIds = messages.stream()
            .map(msg -> msg.getAsMap().get(AuditMessage.REQUEST_ID))
            .filter(id -> id != null)
            .collect(Collectors.toSet());

        // Two requests should produce at least 2 distinct IDs
        assertThat("Different requests should have different IDs", requestIds.size(), greaterThanOrEqualTo(2));
    }

    @Test
    public void shouldShareRequestIdBetweenUserEventAndComplianceEvent() throws Exception {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.putJson(
                "watched-corr/_doc/1",
                "{\"field\":\"compliance-write-test\"}",
                new BasicHeader("X-Request-Id", "compliance-trace-123")
            );
        }

        auditLogsRule.waitForAuditLogs();
        List<AuditMessage> messages = auditLogsRule.getCurrentTestAuditMessages();

        // Find compliance doc write event
        List<AuditMessage> complianceWrites = messages.stream()
            .filter(msg -> msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE)
            .collect(Collectors.toList());

        assertThat("Should produce a COMPLIANCE_DOC_WRITE event", complianceWrites.size(), greaterThanOrEqualTo(1));

        // Compliance event should have the client-provided request ID
        String complianceRequestId = (String) complianceWrites.get(0).getAsMap().get(AuditMessage.REQUEST_ID);
        assertThat("Compliance write event should have request ID", complianceRequestId, equalTo("compliance-trace-123"));

        // User-initiated event (AUTHENTICATED or GRANTED_PRIVILEGES) should share the same ID
        List<AuditMessage> userEvents = messages.stream()
            .filter(msg -> msg.getCategory() == AuditCategory.AUTHENTICATED || msg.getCategory() == AuditCategory.GRANTED_PRIVILEGES)
            .collect(Collectors.toList());
        assertThat("Should produce a user-initiated event", userEvents.size(), greaterThanOrEqualTo(1));
        String userEventRequestId = (String) userEvents.get(0).getAsMap().get(AuditMessage.REQUEST_ID);
        assertThat("User event and compliance event must share the same request ID", userEventRequestId, equalTo(complianceRequestId));
    }

    @Test
    public void shouldStampRequestIdOnAdminCertPath() throws Exception {
        // Admin cert requests still go through SecurityRestFilter on the coordinating node,
        // so they DO get a request ID. This verifies no NPE on the admin cert path.
        try (TestRestClient client = cluster.getRestClient(cluster.getTestCertificates().getAdminCertificateData())) {
            client.putJson("_cluster/settings", "{\"transient\": {\"cluster.routing.allocation.enable\": \"all\"}}");
        }

        auditLogsRule.waitForAuditLogs();
        List<AuditMessage> messages = auditLogsRule.getCurrentTestAuditMessages();

        for (AuditMessage msg : messages) {
            Object requestId = msg.getAsMap().get(AuditMessage.REQUEST_ID);
            // On single-node, all events go through SecurityRestFilter → should have an ID
            assertThat("Events on single-node should have request ID", requestId, notNullValue());
        }
    }
}
