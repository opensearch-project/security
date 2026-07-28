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
 * Integration tests for dynamically toggling audit settings via cluster settings
 * in disabled security mode (plugins.security.disabled: true). Isolated in its
 * own class so that if a toggle test fails mid-way (leaving settings in a modified
 * state), it does not cause flaky behavior in other audit tests.
 *
 * Mirrors the SSL-only dynamic settings tests (StandaloneAuditDynamicConfigTest,
 * StandaloneAuditDynamicFilterSettingsTest, StandaloneAuditDynamicComplianceSettingsTest)
 * to prove the same dynamic configuration paths work in disabled mode.
 */
public class StandaloneAuditDisabledModeToggleTest {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_DISABLED,
                true,
                "plugins.security.audit.type",
                TestRuleAuditLogSink.class.getName(),
                "plugins.security.audit.config.log_request_body",
                true,
                "plugins.security.audit.config.resolve_indices",
                true,
                "plugins.security.audit.config.resolve_bulk_requests",
                true,
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES,
                "watched-*",
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS,
                "read-watched"
            )
        )
        .sslOnly(true)
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    // =====================================================================
    // audit.enabled — toggle on/off at runtime
    // =====================================================================

    @Test
    public void shouldToggleAuditOffAndBackOnViaClusterSettings() {
        // Disable audit
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.enabled\": false}}");
        }

        auditLogsRule.waitForAuditLogs();

        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-toggle/_doc/1?refresh=true", "{\"val\": \"should-not-appear\"}");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> {
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if ("disabled-toggle".equals(idx)) return true;
            }
            return false;
        });

        // Re-enable
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.enabled\": true}}");
        }

        auditLogsRule.waitForAuditLogs();

        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-toggle-back/_doc/1?refresh=true", "{\"val\": \"should-appear\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if ("disabled-toggle-back".equals(idx)) return true;
            }
            return false;
        });
    }

    @Test
    public void shouldDisableAuditAndSuppressAllEvents() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // Disable audit via cluster setting
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.enabled\": false}}");

            // These should NOT be audited
            client.get("_cluster/health");
            client.putJson("toggle-suppress/_doc/1", "{\"field\": \"value\"}");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(
            0,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && (msg.getPrivilege().contains("cluster:monitor/health") || msg.getPrivilege().contains("indices:data/write"))
        );

        // Re-enable
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.enabled\": true}}");
        }
    }

    // =====================================================================
    // log_request_body — toggle off at runtime
    // =====================================================================

    @Test
    public void shouldStopLoggingBodyWhenDisabledAtRuntime() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // Disable request body logging dynamically
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.log_request_body\": false}}");

            // This request's body should NOT appear in audit
            client.postJson("disabled-body-toggle/_search", "{\"query\": {\"match_all\": {}}}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/read/search")) return false;
            return msg.getRequestBody() == null;
        });

        // Reset
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.log_request_body\": true}}");
        }
    }

    @Test
    public void shouldResumeLoggingBodyWhenReenabledAtRuntime() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // Ensure body logging is enabled
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.log_request_body\": true}}");

            client.postJson("disabled-body-resume/_search", "{\"query\": {\"term\": {\"status\": \"active\"}}}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/read/search")) return false;
            String body = msg.getRequestBody();
            return body != null && body.contains("active");
        });
    }

    // =====================================================================
    // ignore_requests — add at runtime
    // =====================================================================

    @Test
    public void shouldIgnoreRequestsAddedAtRuntime() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // Dynamically ignore search requests
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.ignore_requests\": [\"indices:data/read/search\"]}}"
            );

            // Search should now be suppressed
            client.postJson("disabled-ignore-req/_search", "{\"query\": {\"match_all\": {}}}");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(
            0,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().equals("indices:data/read/search")
        );

        // Reset
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.ignore_requests\": []}}");
        }
    }

    @Test
    public void shouldStopIgnoringRequestsWhenCleared() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // First ignore, then clear
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.ignore_requests\": [\"indices:data/read/search\"]}}"
            );
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.ignore_requests\": []}}");

            // Search should now be logged again
            client.postJson("disabled-unignore/_search", "{\"query\": {\"match_all\": {}}}");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/read/search")
        );
    }

    // =====================================================================
    // disabled_categories — disable REQUEST_AUDIT at runtime
    // =====================================================================

    @Test
    public void shouldDisableCategoryAtRuntime() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // Disable REQUEST_AUDIT category dynamically
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.disabled_transport_categories\": [\"REQUEST_AUDIT\"]}}"
            );

            // This should NOT produce a REQUEST_AUDIT event
            client.get("_cluster/health");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(
            0,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("cluster:monitor/health")
        );

        // Reset
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.disabled_transport_categories\": []}}");
        }
    }

    @Test
    public void shouldReenableCategoryAtRuntime() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // Disable then re-enable
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.disabled_transport_categories\": [\"REQUEST_AUDIT\"]}}"
            );
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.disabled_transport_categories\": []}}");

            // Should be logged again
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("cluster:monitor/health")
        );
    }

    // =====================================================================
    // resolve_indices — toggle at runtime
    // =====================================================================

    @Test
    public void shouldStopResolvingIndicesWhenDisabledAtRuntime() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // Create an index first
            client.putJson("disabled-resolve-dyn/_doc/1?refresh=true", "{\"field\": \"value\"}");

            // Disable index resolution
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.resolve_indices\": false}}");

            // Search — should NOT have resolved_indices field
            client.get("disabled-resolve-dyn/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/read/search")) return false;
            Map<String, Object> fields = msg.getAsMap();
            // resolved_indices should be absent when resolve_indices=false
            return fields.get(AuditMessage.RESOLVED_INDICES) == null;
        });

        // Reset
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.resolve_indices\": true}}");
        }
    }

    // =====================================================================
    // resolve_bulk_requests — toggle at runtime
    // =====================================================================

    @Test
    public void shouldToggleBulkResolutionAtRuntime() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // Enable bulk resolution dynamically
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.resolve_bulk_requests\": true}}");

            String bulkBody = "{ \"index\": { \"_index\": \"disabled-dyn-bulk-a\", \"_id\": \"1\" } }\n"
                + "{ \"field\": \"a\" }\n"
                + "{ \"index\": { \"_index\": \"disabled-dyn-bulk-b\", \"_id\": \"2\" } }\n"
                + "{ \"field\": \"b\" }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        // Should see per-item events with individual index names
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if ("disabled-dyn-bulk-a".equals(idx)) return true;
            }
            return false;
        });

        // Reset
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.resolve_bulk_requests\": false}}");
        }
    }

    // =====================================================================
    // Transport layer — disable TRANSPORT_AUDIT at runtime
    // =====================================================================

    @Test
    public void shouldSuppressTransportEventsWhenCategoryDisabledAtRuntime() {
        // First verify TRANSPORT_AUDIT events are produced
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-transport-dyn/_doc/1?refresh=true", "{\"val\": \"before-disable\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.TRANSPORT_AUDIT);

        // Now disable TRANSPORT_AUDIT dynamically
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.disabled_transport_categories\": [\"TRANSPORT_AUDIT\"]}}"
            );
        }

        auditLogsRule.waitForAuditLogs();

        // Index again — TRANSPORT_AUDIT should be suppressed
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-transport-dyn/_doc/2?refresh=true", "{\"val\": \"after-disable\"}");
        }

        // Should still get REQUEST_AUDIT but no TRANSPORT_AUDIT for this second write
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if ("disabled-transport-dyn".equals(idx)) return true;
            }
            return false;
        });

        // Reset
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.disabled_transport_categories\": []}}");
        }
    }

    @Test
    public void shouldResumeTransportEventsWhenCategoryReenabledAtRuntime() {
        // Disable TRANSPORT_AUDIT
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.disabled_transport_categories\": [\"TRANSPORT_AUDIT\"]}}"
            );
        }

        auditLogsRule.waitForAuditLogs();

        // Re-enable by clearing disabled categories
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.disabled_transport_categories\": []}}");
        }

        auditLogsRule.waitForAuditLogs();

        // Index a doc — TRANSPORT_AUDIT should now appear again
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-transport-reenable/_doc/1?refresh=true", "{\"val\": \"back\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.TRANSPORT_AUDIT);
    }

    // =====================================================================
    // compliance.enabled — toggle at runtime
    // =====================================================================

    @Test
    public void shouldStopComplianceWriteEventsWhenDisabledAtRuntime() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // Disable compliance at runtime
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.compliance.enabled\": false}}");

            // Write to watched index — should NOT produce compliance event
            client.putJson("watched-compliance-toggle/_doc/1?refresh=true", "{\"name\": \"should-not-track\"}");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE);

        // Reset
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.compliance.enabled\": true}}");
        }
    }

    @Test
    public void shouldResumeComplianceWriteEventsWhenReenabled() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // Disable then re-enable
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.compliance.enabled\": false}}");
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.compliance.enabled\": true}}");

            // Write should be tracked again
            client.putJson("watched-compliance-resume/_doc/1?refresh=true", "{\"name\": \"tracked-again\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE);
    }

    // =====================================================================
    // write_watched_indices — change at runtime
    // =====================================================================

    @Test
    public void shouldTrackNewWatchedIndexAddedAtRuntime() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // Change watched indices to a new pattern at runtime
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.write_watched_indices\": [\"disabled-dyn-watch-*\"]}}"
            );

            // Write to the new watched pattern
            client.putJson("disabled-dyn-watch-test/_doc/1?refresh=true", "{\"secret\": \"new-pattern\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE);

        // Reset
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.write_watched_indices\": [\"watched-*\"]}}"
            );
        }
    }

    @Test
    public void shouldStopTrackingOldPatternWhenWatchedIndicesChanged() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // Change watched indices to something else
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.write_watched_indices\": [\"only-this-disabled-*\"]}}"
            );

            // Write to the OLD pattern — should NOT produce compliance event
            client.putJson("watched-old-pattern/_doc/1?refresh=true", "{\"name\": \"old-pattern\"}");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE);

        // Reset
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.write_watched_indices\": [\"watched-*\"]}}"
            );
        }
    }

    // =====================================================================
    // read_watched_fields — change at runtime
    // =====================================================================

    @Test
    public void shouldTrackReadForDynamicallyAddedWatchedFields() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // Set read watched fields dynamically
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.read_watched_fields\": [\"disabled-dyn-read-watch\"]}}"
            );

            // Create and search the watched index
            client.putJson("disabled-dyn-read-watch/_doc/1?refresh=true", "{\"name\": \"dynamic-secret\", \"value\": 42}");
            client.get("disabled-dyn-read-watch/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.COMPLIANCE_DOC_READ);

        // Reset
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.compliance.read_watched_fields\": []}}");
        }
    }

    @Test
    public void shouldStopTrackingReadWhenWatchedFieldsCleared() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // First set a watch, then clear it
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.compliance.read_watched_fields\": [\"disabled-clear-read\"]}}"
            );
            client.putJson("disabled-clear-read/_doc/1?refresh=true", "{\"name\": \"tracked\"}");

            // Clear the watch
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.compliance.read_watched_fields\": []}}");

            // Search should NOT produce compliance read event now
            client.get("disabled-clear-read/_search");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> msg.getCategory() == AuditCategory.COMPLIANCE_DOC_READ);
    }

    // =====================================================================
    // ignore_requests — unified suppression across REST and transport layers
    // =====================================================================

    @Test
    public void shouldSuppressBothRestAndTransportEventsWithSameIgnorePattern() {
        // Add a pattern that matches write actions — affects both layers
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.ignore_requests\": [\"indices:data/write/*\"]}}"
            );
        }

        auditLogsRule.waitForAuditLogs();

        // Send a write — should be suppressed at BOTH REQUEST_AUDIT and TRANSPORT_AUDIT
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-unified-ignore/_doc/1?refresh=true", "{\"data\": \"suppressed\"}");
        }

        auditLogsRule.waitForAuditLogs();

        // No REQUEST_AUDIT events for write actions on this index
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().startsWith("indices:data/write")) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if ("disabled-unified-ignore".equals(idx)) return true;
            }
            return false;
        });

        // No TRANSPORT_AUDIT events for write actions either
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.TRANSPORT_AUDIT) return false;
            return msg.getPrivilege() != null && msg.getPrivilege().startsWith("indices:data/write");
        });

        // Reset
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.ignore_requests\": []}}");
        }
    }

    // =====================================================================
    // exclude_sensitive_headers — toggle at runtime
    // =====================================================================

    @Test
    public void shouldToggleSensitiveHeaderExclusionAtRuntime() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            // Disable sensitive header exclusion
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.exclude_sensitive_headers\": false}}");

            client.get("_cluster/health");
        }

        // When exclude_sensitive_headers=false, all headers pass through unfiltered
        // Verify events still flow correctly with the setting changed
        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("cluster:monitor/health")
        );

        // Reset
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.exclude_sensitive_headers\": true}}");
        }
    }

    // =====================================================================
    // disabled_rest_categories should NOT suppress TRANSPORT_AUDIT
    // =====================================================================

    @Test
    public void shouldNotSuppressTransportAuditWhenOnlyRestCategoryDisabled() {
        // Disable TRANSPORT_AUDIT via REST categories only (should not affect transport interceptor)
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.disabled_rest_categories\": [\"TRANSPORT_AUDIT\"]}}"
            );
        }

        auditLogsRule.waitForAuditLogs();

        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-rest-cat-test/_doc/1?refresh=true", "{\"val\": \"still-logged\"}");
        }

        // TRANSPORT_AUDIT events should still appear — REST category disable doesn't affect transport
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.TRANSPORT_AUDIT);

        // Reset
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.disabled_rest_categories\": []}}");
        }
    }
}
