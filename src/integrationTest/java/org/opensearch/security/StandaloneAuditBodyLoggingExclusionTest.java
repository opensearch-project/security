/*
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
 * Integration tests for body logging exclusions in SSL-only mode.
 * Verifies that AuditActionFilter respects body exclusion patterns.
 */
public class StandaloneAuditBodyLoggingExclusionTest {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY,
                true,
                "plugins.security.audit.type",
                TestRuleAuditLogSink.class.getName(),
                "plugins.security.audit.config.log_request_body",
                true,
                "plugins.security.audit.config.action_groups.BULK",
                "indices:data/write/bulk*,/_bulk",
                "plugins.security.audit.config.action_groups.SEARCH",
                "indices:data/read/search*,/_search",
                "plugins.security.audit.config.body_logging_exclusions",
                "BULK"
            )
        )
        .sslOnly(true)
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void shouldExcludeBodyForBulkInSslOnlyMode() {
        try (TestRestClient client = cluster.getRestClient()) {
            String bulkBody = "{ \"index\": { \"_index\": \"ssl-test\", \"_id\": \"1\" } }\n" + "{ \"field\": \"should-not-appear\" }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        // REQUEST_AUDIT event for bulk — body should be excluded
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write/bulk")) return false;
            return msg.getRequestBody() == null;
        });
    }

    @Test
    public void shouldLogBodyForNonExcludedInSslOnlyMode() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("ssl-test/_doc/1", "{\"field\": \"should-appear\"}");
        }

        // REQUEST_AUDIT event for single index — body should be present
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write/index")) return false;
            String body = msg.getRequestBody();
            return body != null && body.contains("should-appear");
        });
    }

    @Test
    public void shouldDynamicallyAddExclusionAtRuntime() {
        // First verify search body IS logged
        try (TestRestClient client = cluster.getRestClient()) {
            client.postJson("ssl-test/_search", "{\"query\": {\"match_all\": {}}}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/read/search")) return false;
            String body = msg.getRequestBody();
            return body != null && body.contains("match_all");
        });

        // Now dynamically add SEARCH to exclusions
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.body_logging_exclusions\": [\"BULK\", \"SEARCH\"]}}"
            );
        }

        auditLogsRule.waitForAuditLogs();

        // Search body should now be excluded
        try (TestRestClient client = cluster.getRestClient()) {
            client.postJson("ssl-test/_search", "{\"query\": {\"term\": {\"field\": \"dynamic-test\"}}}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/read/search")) return false;
            // After dynamic update — body should be null for search
            return msg.getRequestBody() == null;
        });

        // Reset
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.body_logging_exclusions\": [\"BULK\"]}}"
            );
        }
    }

    @Test
    public void shouldWorkWithRawPatternNotGroupName() {
        // Dynamically set a raw pattern (not a group name)
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.body_logging_exclusions\": [\"BULK\", \"indices:data/write/update*\"]}}"
            );
        }

        auditLogsRule.waitForAuditLogs();

        // Update request body should be excluded (matches raw pattern)
        try (TestRestClient client = cluster.getRestClient()) {
            client.postJson("ssl-test/_update/1", "{\"doc\": {\"field\": \"updated-should-not-appear\"}}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write/update")) return false;
            return msg.getRequestBody() == null;
        });

        // Reset
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.body_logging_exclusions\": [\"BULK\"]}}"
            );
        }
    }

    @Test
    public void shouldMatchShardLevelActionWithWildcard() {
        // "indices:data/write/bulk*" should match "indices:data/write/bulk[s][p]"
        try (TestRestClient client = cluster.getRestClient()) {
            String bulkBody = "{ \"index\": { \"_index\": \"shard-test\", \"_id\": \"1\" } }\n" + "{ \"field\": \"shard-level-body\" }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write/bulk")) return false;
            return msg.getRequestBody() == null;
        });
    }

    @Test
    public void shouldRemoveAllExclusionsAtRuntime() {
        // Clear all exclusions — bodies should be logged for everything again
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.body_logging_exclusions\": []}}");
        }

        auditLogsRule.waitForAuditLogs();

        // Use a single index request (not bulk) to verify body appears after clearing exclusions.
        // BulkRequest body is not extracted by addRequestBody() — only IndexRequest/SearchRequest/UpdateRequest are.
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("cleared-test/_doc/1", "{\"field\": \"now-visible\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write/index")) return false;
            String body = msg.getRequestBody();
            return body != null && body.contains("now-visible");
        });

        // Restore exclusions
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.body_logging_exclusions\": [\"BULK\"]}}"
            );
        }
    }

    @Test
    public void shouldHandleMultipleGroupsInExclusions() {
        // Exclude both BULK and SEARCH
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.body_logging_exclusions\": [\"BULK\", \"SEARCH\"]}}"
            );
        }

        auditLogsRule.waitForAuditLogs();

        // Search body should be excluded
        try (TestRestClient client = cluster.getRestClient()) {
            client.postJson("ssl-test/_search", "{\"query\": {\"match_all\": {}}}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/read/search")) return false;
            return msg.getRequestBody() == null;
        });

        // But single index should still have body (not in any exclusion group)
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("ssl-test/_doc/99", "{\"field\": \"multi-group-test\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write/index")) return false;
            String body = msg.getRequestBody();
            return body != null && body.contains("multi-group-test");
        });

        // Reset
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.body_logging_exclusions\": [\"BULK\"]}}"
            );
        }
    }

    @Test
    public void shouldTreatNonExistentGroupAsRawPattern() {
        // "FAKE_GROUP" doesn't exist — treated as raw pattern (won't match anything useful)
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.body_logging_exclusions\": [\"FAKE_GROUP\"]}}"
            );
        }

        auditLogsRule.waitForAuditLogs();

        // Nothing matches "FAKE_GROUP" as a pattern — body still logged
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("ssl-test/_doc/100", "{\"field\": \"not-excluded\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write/index")) return false;
            String body = msg.getRequestBody();
            return body != null && body.contains("not-excluded");
        });

        // Reset
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson(
                "_cluster/settings",
                "{\"persistent\": {\"plugins.security.audit.config.body_logging_exclusions\": [\"BULK\"]}}"
            );
        }
    }

    @Test
    public void shouldNotLogAnyBodyWhenGlobalToggleOff() {
        // Disable body logging globally — exclusions become irrelevant
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.log_request_body\": false}}");
        }

        auditLogsRule.waitForAuditLogs();

        // Even non-excluded requests should have no body
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("global-off-test/_doc/1", "{\"field\": \"should-not-appear\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write/index")) return false;
            return msg.getRequestBody() == null;
        });

        // Reset
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.log_request_body\": true}}");
        }
    }
}
