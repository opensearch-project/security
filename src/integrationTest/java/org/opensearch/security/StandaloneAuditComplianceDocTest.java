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
 * Integration tests for document-level compliance tracking (COMPLIANCE_DOC_WRITE
 * and COMPLIANCE_DOC_READ) in SSL-only mode. Verifies that the
 * ComplianceIndexingOperationListenerImpl and ComplianceReadIndexSearcherWrapper
 * produce correct events without FGAC.
 */
public class StandaloneAuditComplianceDocTest {

    // --- Cluster with compliance write tracking enabled ---
    @ClassRule
    public static LocalCluster writeCluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY, true,
                "plugins.security.audit.type", TestRuleAuditLogSink.class.getName(),
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, "watched-*"
            )
        )
        .sslOnly(true)
        .build();

    // --- Cluster with compliance read tracking enabled ---
    @ClassRule
    public static LocalCluster readCluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY, true,
                "plugins.security.audit.type", TestRuleAuditLogSink.class.getName(),
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, "read-watched"
            )
        )
        .sslOnly(true)
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    // =====================================================================
    // COMPLIANCE_DOC_WRITE
    // =====================================================================

    @Test
    public void shouldProduceComplianceDocWriteForWatchedIndex() {
        try (TestRestClient client = writeCluster.getRestClient()) {
            client.putJson("watched-index/_doc/1?refresh=true", "{\"name\": \"sensitive\", \"ssn\": \"123-45-6789\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );
    }

    @Test
    public void shouldNotProduceComplianceDocWriteForUnwatchedIndex() {
        try (TestRestClient client = writeCluster.getRestClient()) {
            client.putJson("unwatched-index/_doc/1?refresh=true", "{\"name\": \"not-tracked\"}");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );
    }

    @Test
    public void shouldCaptureDocIdInComplianceWriteEvent() {
        try (TestRestClient client = writeCluster.getRestClient()) {
            client.putJson("watched-docs/_doc/my-unique-id?refresh=true", "{\"field\": \"value\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.COMPLIANCE_DOC_WRITE) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object docId = fields.get(AuditMessage.ID);
            return "my-unique-id".equals(docId);
        });
    }

    @Test
    public void shouldProduceComplianceWriteForBulkToWatchedIndex() {
        try (TestRestClient client = writeCluster.getRestClient()) {
            String bulkBody = "{ \"index\": { \"_index\": \"watched-bulk\", \"_id\": \"bulk-1\" } }\n"
                + "{ \"data\": \"bulk-write\" }\n"
                + "{ \"index\": { \"_index\": \"watched-bulk\", \"_id\": \"bulk-2\" } }\n"
                + "{ \"data\": \"another-write\" }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        // Should produce compliance write events for each doc
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );
    }

    @Test
    public void shouldProduceComplianceWriteForUpdateToWatchedIndex() {
        try (TestRestClient client = writeCluster.getRestClient()) {
            client.putJson("watched-update/_doc/1?refresh=true", "{\"field\": \"original\"}");
            client.postJson("watched-update/_update/1?refresh=true", "{\"doc\": {\"field\": \"modified\"}}");
        }

        // Update should also trigger compliance write
        auditLogsRule.assertAtLeast(2, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );
    }

    @Test
    public void shouldProduceComplianceWriteForDeleteFromWatchedIndex() {
        try (TestRestClient client = writeCluster.getRestClient()) {
            client.putJson("watched-delete/_doc/1?refresh=true", "{\"field\": \"to-delete\"}");
            client.delete("watched-delete/_doc/1?refresh=true");
        }

        // Delete from watched index should also produce compliance event
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );
    }

    @Test
    public void shouldMatchWildcardPatternForWatchedWriteIndex() {
        try (TestRestClient client = writeCluster.getRestClient()) {
            // "watched-*" pattern should match "watched-logs-2026"
            client.putJson("watched-logs-2026/_doc/1?refresh=true", "{\"data\": \"wildcard-match\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_WRITE
        );
    }

    @Test
    public void shouldCaptureShardIdInComplianceWriteEvent() {
        try (TestRestClient client = writeCluster.getRestClient()) {
            client.putJson("watched-shard/_doc/1?refresh=true", "{\"field\": \"shard-test\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.COMPLIANCE_DOC_WRITE) return false;
            Map<String, Object> fields = msg.getAsMap();
            return fields.get(AuditMessage.SHARD_ID) != null;
        });
    }

    // =====================================================================
    // COMPLIANCE_DOC_READ
    // =====================================================================

    @Test
    public void shouldProduceComplianceDocReadForWatchedFields() {
        try (TestRestClient client = readCluster.getRestClient()) {
            // Index a doc with watched fields
            client.putJson("read-watched/_doc/1?refresh=true", "{\"name\": \"secret-name\", \"public\": \"visible\"}");
            // Read it back — triggers compliance read
            client.get("read-watched/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_READ
        );
    }

    @Test
    public void shouldNotProduceComplianceDocReadForUnwatchedIndex() {
        try (TestRestClient client = readCluster.getRestClient()) {
            client.putJson("not-read-watched/_doc/1?refresh=true", "{\"name\": \"not-tracked\"}");
            client.get("not-read-watched/_search");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_READ
        );
    }

    @Test
    public void shouldCaptureFieldValuesInComplianceReadEvent() {
        try (TestRestClient client = readCluster.getRestClient()) {
            client.putJson("read-watched/_doc/2?refresh=true", "{\"name\": \"field-value-test\", \"age\": 30}");
            client.get("read-watched/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.COMPLIANCE_DOC_READ) return false;
            String body = msg.getRequestBody();
            return body != null && body.contains("field-value-test");
        });
    }

    @Test
    public void shouldProduceComplianceReadForGetById() {
        try (TestRestClient client = readCluster.getRestClient()) {
            client.putJson("read-watched/_doc/get-test?refresh=true", "{\"name\": \"get-by-id\"}");
            client.get("read-watched/_doc/get-test");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_READ
        );
    }

    @Test
    public void shouldProduceMultipleReadEventsForMultipleDocs() {
        try (TestRestClient client = readCluster.getRestClient()) {
            client.putJson("read-watched/_doc/multi-1?refresh=true", "{\"name\": \"first\"}");
            client.putJson("read-watched/_doc/multi-2?refresh=true", "{\"name\": \"second\"}");
            client.putJson("read-watched/_doc/multi-3?refresh=true", "{\"name\": \"third\"}");
            // Search returns all 3 — should produce a read event per doc
            client.postJson("read-watched/_search", "{\"query\": {\"match_all\": {}}}");
        }

        auditLogsRule.assertAtLeast(3, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.COMPLIANCE_DOC_READ
        );
    }

    @Test
    public void shouldCaptureDocIdInComplianceReadEvent() {
        try (TestRestClient client = readCluster.getRestClient()) {
            client.putJson("read-watched/_doc/read-id-check?refresh=true", "{\"name\": \"id-test\"}");
            client.get("read-watched/_doc/read-id-check");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.COMPLIANCE_DOC_READ) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object docId = fields.get(AuditMessage.ID);
            return "read-id-check".equals(docId);
        });
    }
}
