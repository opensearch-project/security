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
 * Integration tests verifying that dynamic compliance settings can be
 * changed at runtime via PUT _cluster/settings without a node restart.
 * Tests compliance.enabled and write_watched_indices dynamic toggling.
 */
public class StandaloneAuditDynamicComplianceSettingsTest {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY, true,
                "plugins.security.audit.type", TestRuleAuditLogSink.class.getName(),
                // Start with compliance enabled and watching "compliance-*" indices
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES,
                "compliance-*"
            )
        )
        .sslOnly(true)
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    // =====================================================================
    // compliance.enabled — toggle at runtime
    // =====================================================================

    @Test
    public void shouldProduceComplianceWriteEventsWhenEnabled() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Ensure compliance is enabled
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.enabled\": true}}");

            // Write to a watched index
            client.putJson("compliance-test/_doc/1?refresh=true", "{\"name\": \"sensitive-data\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );
    }

    @Test
    public void shouldStopComplianceWriteEventsWhenDisabledAtRuntime() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Disable compliance at runtime
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.enabled\": false}}");

            // Write to watched index — should NOT produce compliance event
            client.putJson("compliance-test/_doc/2?refresh=true", "{\"name\": \"should-not-track\"}");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );

        // Reset
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.enabled\": true}}");
        }
    }

    @Test
    public void shouldResumeComplianceWriteEventsWhenReenabled() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Disable then re-enable
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.enabled\": false}}");
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.enabled\": true}}");

            // Write should be tracked again
            client.putJson("compliance-test/_doc/3?refresh=true", "{\"name\": \"tracked-again\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );
    }

    // =====================================================================
    // write_watched_indices — change at runtime
    // =====================================================================

    @Test
    public void shouldTrackNewWatchedIndexAddedAtRuntime() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Change watched indices to a new pattern at runtime
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.write_watched_indices\": [\"dynamic-watch-*\"]}}");

            // Write to the new watched pattern
            client.putJson("dynamic-watch-test/_doc/1?refresh=true", "{\"secret\": \"new-pattern\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );

        // Reset
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.write_watched_indices\": [\"compliance-*\"]}}");
        }
    }

    @Test
    public void shouldStopTrackingOldPatternWhenWatchedIndicesChanged() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Change watched indices to something else
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.write_watched_indices\": [\"only-this-*\"]}}");

            // Write to the OLD pattern — should NOT produce compliance event
            client.putJson("compliance-test/_doc/4?refresh=true", "{\"name\": \"old-pattern\"}");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );

        // Reset
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.write_watched_indices\": [\"compliance-*\"]}}");
        }
    }

    // =====================================================================
    // read_watched_fields — change at runtime
    // =====================================================================

    @Test
    public void shouldTrackReadForDynamicallyAddedWatchedFields() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Set read watched fields dynamically
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.read_watched_fields\": [\"dynamic-read-watch\"]}}");

            // Create and search the watched index
            client.putJson("dynamic-read-watch/_doc/1?refresh=true", "{\"name\": \"dynamic-secret\", \"value\": 42}");
            client.get("dynamic-read-watch/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_READ
        );

        // Reset
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.read_watched_fields\": []}}");
        }
    }

    @Test
    public void shouldStopTrackingReadWhenWatchedFieldsCleared() {
        try (TestRestClient client = cluster.getRestClient()) {
            // First set a watch, then clear it
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.read_watched_fields\": [\"clear-read-test\"]}}");
            client.putJson("clear-read-test/_doc/1?refresh=true", "{\"name\": \"tracked\"}");

            // Clear the watch
            client.putJson("_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.read_watched_fields\": []}}");

            // Search should NOT produce compliance read event now
            client.get("clear-read-test/_search");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_READ
        );
    }
}
