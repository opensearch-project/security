/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security;

import java.util.List;
import java.util.Map;

import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.audit.TestRuleAuditLogSink;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

/**
 * Integration test verifying that transport-layer intercept events
 * (from AuditTransportInterceptor) are visible in SSL-only mode.
 * Uses a 2-node cluster to generate real inter-node transport traffic.
 */
public class StandaloneAuditTransportInterceptTest {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY,
                true,
                "plugins.security.audit.type",
                TestRuleAuditLogSink.class.getName(),
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT,
                true,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS,
                List.of("cluster:monitor/*", "indices:monitor/*")
            )
        )
        .sslOnly(true)
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void shouldProduceTransportEventsForIndexWrite() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Index a doc — this will route to primary shard, possibly on another node
            client.putJson("transport-test/_doc/1?refresh=true", "{\"field\": \"value\"}");
        }

        // Transport intercept should capture shard-level write actions
        // These have action names with suffixes like [s][p] or [s][r]
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.TRANSPORT_AUDIT) return false;
            return msg.getPrivilege() != null && msg.getPrivilege().contains("[s][p]");
        });
    }

    @Test
    public void shouldNotLogClusterMonitorTransportActions() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("_cluster/health");
            client.get("_nodes/stats");
        }

        auditLogsRule.waitForAuditLogs();
        // The transport interceptor skips cluster:monitor/* — so no shard-level
        // transport forwarding events should appear for monitor actions.
        // The AuditActionFilter still logs the top-level monitor action (that's correct),
        // but we should NOT see forwarded transport events with [p] or [r] suffixes for monitors.
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.TRANSPORT_AUDIT) return false;
            if (msg.getPrivilege() == null) return false;
            // Shard-level forwarded actions have suffixes like [p], [r], [s]
            return msg.getPrivilege().startsWith("cluster:monitor/") && msg.getPrivilege().contains("[");
        });
    }
}
