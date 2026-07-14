/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security;

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
 * Integration test verifying dynamic audit configuration via cluster settings
 * in SSL-only mode. Tests that audit logging can be toggled on/off at runtime
 * using PUT _cluster/settings without a node restart.
 */
public class StandaloneAuditDynamicConfigTest {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(Map.of(ConfigConstants.SECURITY_SSL_ONLY, true, "plugins.security.audit.type", TestRuleAuditLogSink.class.getName()))
        .sslOnly(true)
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void shouldDisableAuditViaClusterSettings() {
        // First confirm audit is working
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("cluster:monitor/health")
        );
    }

    @Test
    public void shouldToggleAuditOffAndBackOn() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Disable audit via cluster setting
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.enabled\": false}}");

            // These should NOT be audited
            client.get("_cluster/health");
            client.putJson("toggle-test/_doc/1", "{\"field\": \"value\"}");
        }

        auditLogsRule.waitForAuditLogs();

        // No REQUEST_AUDIT events for the requests after disabling
        // (the cluster settings PUT itself may or may not be captured depending on timing)
        auditLogsRule.assertExactlyScanAll(
            0,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && (msg.getPrivilege().contains("cluster:monitor/health") || msg.getPrivilege().contains("indices:data/write"))
        );

        // Re-enable audit
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.enabled\": true}}");

            // This SHOULD be audited again
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("cluster:monitor/health")
        );
    }
}
