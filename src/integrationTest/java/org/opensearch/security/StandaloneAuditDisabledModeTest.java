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
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.opensearch.security.DisabledModeAuditTestUtils.messageMatchesIndex;

/**
 * Comprehensive integration tests for audit logging in disabled security mode
 * (plugins.security.disabled: true). Verifies that REQUEST_AUDIT, TRANSPORT_AUDIT,
 * COMPLIANCE_DOC_WRITE, and COMPLIANCE_DOC_READ all function correctly when the
 * security plugin is disabled but audit logging is configured.
 *
 * These tests mirror the ssl-only mode tests to prove the same code paths work
 * identically in disabled mode after the onIndexModule gate change.
 */
public class StandaloneAuditDisabledModeTest {

    @ClassRule
    public static LocalCluster cluster = DisabledModeAuditTestUtils.createDisabledModeAuditCluster();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    // =====================================================================
    // REQUEST_AUDIT — basic event production
    // =====================================================================

    @Test
    public void shouldProduceRequestAuditForIndexWrite() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-test/_doc/1?refresh=true", "{\"msg\": \"hello from disabled mode\"}");
        }

        auditLogsRule.assertAtLeast(1, msg -> messageMatchesIndex(msg, AuditCategory.REQUEST_AUDIT, "disabled-test"));
    }

    @Test
    public void shouldProduceRequestAuditForSearch() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-search/_doc/1?refresh=true", "{\"field\": \"value\"}");
            client.postJson("disabled-search/_search", "{\"query\": {\"match_all\": {}}}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            return msg.getPrivilege() != null && msg.getPrivilege().contains("indices:data/read/search");
        });
    }

    @Test
    public void shouldCaptureRemoteAddressInDisabledMode() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            return fields.get(AuditMessage.REMOTE_ADDRESS) != null;
        });
    }

    @Test
    public void shouldNotHaveEffectiveUserInDisabledMode() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-nouser/_doc/1?refresh=true", "{\"data\": \"test\"}");
        }

        // In disabled mode without mTLS client auth, there's no user identity
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (!messageMatchesIndex(msg, AuditCategory.REQUEST_AUDIT, "disabled-nouser")) return false;
            Map<String, Object> fields = msg.getAsMap();
            // effective_user should be absent (no auth in disabled mode)
            return fields.get(AuditMessage.REQUEST_EFFECTIVE_USER) == null;
        });
    }

    @Test
    public void shouldLogRequestBody() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-body/_doc/1?refresh=true", "{\"secret\": \"disabled-mode-payload\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            String body = msg.getRequestBody();
            return body != null && body.contains("disabled-mode-payload");
        });
    }

    @Test
    public void shouldLogRestHeaders() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-headers/_doc/1?refresh=true", "{\"data\": \"headers-test\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            return fields.get(AuditMessage.REST_REQUEST_HEADERS) != null;
        });
    }

    // =====================================================================
    // REQUEST_AUDIT — bulk handling
    // =====================================================================

    @Test
    public void shouldLogPerItemEventsForBulkInDisabledMode() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            String bulkBody = "{ \"index\": { \"_index\": \"disabled-bulk-a\", \"_id\": \"1\" } }\n"
                + "{ \"field\": \"value-a\" }\n"
                + "{ \"index\": { \"_index\": \"disabled-bulk-b\", \"_id\": \"2\" } }\n"
                + "{ \"field\": \"value-b\" }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        auditLogsRule.assertAtLeast(1, msg -> messageMatchesIndex(msg, AuditCategory.REQUEST_AUDIT, "disabled-bulk-a"));
        auditLogsRule.assertAtLeast(1, msg -> messageMatchesIndex(msg, AuditCategory.REQUEST_AUDIT, "disabled-bulk-b"));
    }

    // =====================================================================
    // TRANSPORT_AUDIT — inter-node events
    // =====================================================================

    @Test
    public void shouldProduceTransportAuditEventsInDisabledMode() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-transport/_doc/1?refresh=true", "{\"val\": \"transport-test\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.TRANSPORT_AUDIT);
    }

    @Test
    public void shouldCaptureShardActionInTransportEvent() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-shard/_doc/1?refresh=true", "{\"val\": \"shard-test\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.TRANSPORT_AUDIT) return false;
            return msg.getPrivilege() != null && msg.getPrivilege().contains("[s][p]");
        });
    }

    // =====================================================================
    // COMPLIANCE_DOC_WRITE — document write tracking
    // =====================================================================

    @Test
    public void shouldProduceComplianceDocWriteForWatchedIndex() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("watched-disabled/_doc/1?refresh=true", "{\"name\": \"sensitive\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE);
    }

    @Test
    public void shouldNotProduceComplianceDocWriteForUnwatchedIndex() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("unwatched-disabled/_doc/1?refresh=true", "{\"name\": \"not-tracked\"}");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.COMPLIANCE_DOC_WRITE) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.RESOLVED_INDICES);
            return indices != null && indices.toString().contains("unwatched-disabled");
        });
    }

    @Test
    public void shouldCaptureDocIdInComplianceWriteEvent() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("watched-docid-disabled/_doc/my-id-123?refresh=true", "{\"field\": \"value\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.COMPLIANCE_DOC_WRITE) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object docId = fields.get(AuditMessage.ID);
            return "my-id-123".equals(docId);
        });
    }

    @Test
    public void shouldProduceComplianceWriteForUpdateInDisabledMode() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("watched-update-disabled/_doc/1?refresh=true", "{\"field\": \"original\"}");
            client.postJson("watched-update-disabled/_update/1?refresh=true", "{\"doc\": {\"field\": \"modified\"}}");
        }

        auditLogsRule.assertAtLeast(2, (AuditMessage msg) -> msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE);
    }

    @Test
    public void shouldProduceComplianceWriteForDeleteInDisabledMode() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("watched-delete-disabled/_doc/1?refresh=true", "{\"field\": \"to-delete\"}");
            client.delete("watched-delete-disabled/_doc/1?refresh=true");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE);
    }

    @Test
    public void shouldMatchWildcardPatternForWatchedWriteIndex() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("watched-logs-disabled-2026/_doc/1?refresh=true", "{\"data\": \"wildcard-match\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE);
    }

    // =====================================================================
    // COMPLIANCE_DOC_READ — document read tracking
    // =====================================================================

    @Test
    public void shouldProduceComplianceDocReadForWatchedFields() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("read-watched/_doc/1?refresh=true", "{\"name\": \"secret-name\", \"public\": \"visible\"}");
            client.get("read-watched/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.COMPLIANCE_DOC_READ);
    }

    @Test
    public void shouldNotProduceComplianceDocReadForUnwatchedIndex() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("not-read-watched-disabled/_doc/1?refresh=true", "{\"name\": \"not-tracked\"}");
            client.get("not-read-watched-disabled/_search");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> msg.getCategory() == AuditCategory.COMPLIANCE_DOC_READ);
    }

    @Test
    public void shouldProduceComplianceReadForGetById() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("read-watched/_doc/get-disabled?refresh=true", "{\"name\": \"get-by-id\"}");
            client.get("read-watched/_doc/get-disabled");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.COMPLIANCE_DOC_READ);
    }

    // =====================================================================
    // Index resolution — wildcards still resolve in disabled mode
    // =====================================================================

    @Test
    public void shouldResolveWildcardIndicesToActualNames() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-resolve-test/_doc/1?refresh=true", "{\"field\": \"value\"}");
            client.get("disabled-resolve-*/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object resolved = fields.get(AuditMessage.RESOLVED_INDICES);
            if (resolved == null) return false;
            String[] resolvedArr = (String[]) resolved;
            for (String idx : resolvedArr) {
                if ("disabled-resolve-test".equals(idx)) return true;
            }
            return false;
        });
    }

    // =====================================================================
    // Ignore patterns — verify filtering works in disabled mode
    // =====================================================================

    @Test
    public void shouldNeverLogInternalActions() {
        // Internal actions are always suppressed — just do a normal request and
        // verify no internal:* events appear
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("disabled-internal/_doc/1?refresh=true", "{\"data\": \"test\"}");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> {
            return msg.getPrivilege() != null && msg.getPrivilege().startsWith("internal:");
        });
    }

    // =====================================================================
    // Self-loop guard — audit index writes not audited
    // =====================================================================

    @Test
    public void shouldNotProduceEventsForAuditIndexWrites() {
        // Write directly to an index matching the audit index prefix
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.putJson("security-auditlog-2026.07.14/_doc/1?refresh=true", "{\"audit\": \"self-loop-test\"}");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if (idx != null && idx.startsWith("security-auditlog")) return true;
            }
            return false;
        });
    }
}
