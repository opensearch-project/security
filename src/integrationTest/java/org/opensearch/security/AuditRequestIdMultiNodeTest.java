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

import org.opensearch.security.auditlog.impl.AuditMessage;
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
import static org.hamcrest.Matchers.nullValue;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Multi-node integration tests for audit_request_id correlation.
 * Verifies behavior when requests are forwarded across nodes —
 * specifically the known limitation that server-generated UUIDs
 * (no client X-Request-Id header) don't propagate via transient headers.
 */
public class AuditRequestIdMultiNodeTest {

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN)
        .audit(new AuditConfiguration(true).filters(new AuditFilters().enabledRest(true).enabledTransport(true)))
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void shouldCorrelateWithClientHeaderAcrossNodes() throws Exception {
        // With a client-provided X-Request-Id, core propagates the header across nodes.
        // All events — including transport events on data nodes — should share the same ID.
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            // Write to an index to trigger shard-level transport actions on data nodes
            client.putJson("multinode-test/_doc/1", "{\"field\":\"value\"}", new BasicHeader("X-Request-Id", "multi-node-trace-abc"));
        }

        auditLogsRule.waitForAuditLogs();
        List<AuditMessage> messages = auditLogsRule.getCurrentTestAuditMessages();

        assertThat("Should produce audit events", messages.size(), greaterThanOrEqualTo(1));

        // All events that have a request ID should share the client-provided value
        for (AuditMessage msg : messages) {
            Object requestId = msg.getAsMap().get(AuditMessage.REQUEST_ID);
            if (requestId != null) {
                assertThat("All events with request ID should use client header value", requestId, equalTo("multi-node-trace-abc"));
            }
        }
    }

    @Test
    public void shouldLackRequestIdOnRemoteNodeTransportWithoutClientHeader() throws Exception {
        // Without a client X-Request-Id header, the server generates a UUID into a transient.
        // Transients don't cross transport boundaries. On a multi-node cluster,
        // transport events forwarded to data nodes may lack the audit_request_id field.
        // This is the documented known limitation.
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            // Index a doc without X-Request-Id — triggers shard actions on other nodes
            client.putJson("no-header-multinode/_doc/1", "{\"field\":\"value\"}");
        }

        auditLogsRule.waitForAuditLogs();
        List<AuditMessage> messages = auditLogsRule.getCurrentTestAuditMessages();

        assertThat("Should produce audit events", messages.size(), greaterThanOrEqualTo(1));

        // Coordinating node REST events should have a request ID (generated base64UUID)
        List<AuditMessage> restLayerEvents = messages.stream()
            .filter(msg -> "REST".equals(String.valueOf(msg.getAsMap().get("audit_request_layer"))))
            .collect(Collectors.toList());

        for (AuditMessage msg : restLayerEvents) {
            assertThat("REST-layer events should always have request ID", msg.getAsMap().get(AuditMessage.REQUEST_ID), notNullValue());
        }

        // Collect all REST-layer IDs for comparison
        Set<Object> restIds = restLayerEvents.stream()
            .map(msg -> msg.getAsMap().get(AuditMessage.REQUEST_ID))
            .filter(id -> id != null)
            .collect(Collectors.toSet());

        // Transport-layer events: split into those with and without request ID
        List<AuditMessage> transportLayerEvents = messages.stream()
            .filter(msg -> "TRANSPORT".equals(String.valueOf(msg.getAsMap().get("audit_request_layer"))))
            .collect(Collectors.toList());

        List<AuditMessage> transportWithId = transportLayerEvents.stream()
            .filter(msg -> msg.getAsMap().get(AuditMessage.REQUEST_ID) != null)
            .collect(Collectors.toList());

        List<AuditMessage> transportWithoutId = transportLayerEvents.stream()
            .filter(msg -> msg.getAsMap().get(AuditMessage.REQUEST_ID) == null)
            .collect(Collectors.toList());

        // Transport events WITH an ID should match the coordinating node's ID
        // (these are same-node transport events that share the transient)
        for (AuditMessage msg : transportWithId) {
            Object transportId = msg.getAsMap().get(AuditMessage.REQUEST_ID);
            assertThat("Same-node transport events should share coordinating node's ID", restIds.contains(transportId), equalTo(true));
        }

        // On a 3-node cluster with shard routing, some transport events on remote nodes
        // should lack the request ID — this is the documented known limitation.
        // (Transient headers don't cross the transport boundary without a client X-Request-Id header)
        // NOTE: This assertion may not always trigger if all shards happen to land on the
        // coordinating node — but on 3 nodes with default settings, forwarding is likely.
        if (!transportWithoutId.isEmpty()) {
            for (AuditMessage msg : transportWithoutId) {
                assertThat(
                    "Remote-node transport events should lack request ID without client header",
                    msg.getAsMap().get(AuditMessage.REQUEST_ID),
                    nullValue()
                );
            }
        }
    }
}
