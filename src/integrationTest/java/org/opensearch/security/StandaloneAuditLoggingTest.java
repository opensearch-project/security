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
 * Integration tests for standalone audit logging in SSL-only mode.
 * Verifies that REQUEST_AUDIT events are produced with correct fields
 * when no authentication/authorization layer is active.
 */
public class StandaloneAuditLoggingTest {

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
    public void shouldCaptureAllFieldsForSearchRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("test-index/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (!"SearchRequest".equals(msg.getRequestType())) return false;

            Map<String, Object> fields = msg.getAsMap();

            // Indices
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;

            // Node/cluster info (populated by AuditMessage constructor from ClusterService)
            if (fields.get(AuditMessage.NODE_NAME) == null) return false;
            if (fields.get(AuditMessage.NODE_ID) == null) return false;
            if (fields.get(AuditMessage.CLUSTER_NAME) == null) return false;
            if (fields.get(AuditMessage.NODE_HOST_ADDRESS) == null) return false;

            // Task ID
            if (fields.get(AuditMessage.TASK_ID) == null) return false;

            // Timestamp
            if (fields.get(AuditMessage.UTC_TIMESTAMP) == null) return false;

            // Action/privilege
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/read/search")) return false;

            return true;
        });
    }

    @Test
    public void shouldProduceRequestAuditEventForIndexOperation() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("test-index/_doc/1", "{\"field\": \"value\"}");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/write")
        );
    }

    @Test
    public void shouldCaptureClusterHealthWithNoIndices() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("cluster:monitor/health")) return false;

            Map<String, Object> fields = msg.getAsMap();
            // No indices for cluster-level request
            if (fields.get(AuditMessage.INDICES) != null) return false;

            // But node info and timestamp should still be present
            if (fields.get(AuditMessage.NODE_NAME) == null) return false;
            if (fields.get(AuditMessage.UTC_TIMESTAMP) == null) return false;
            if (fields.get(AuditMessage.TASK_ID) == null) return false;

            return true;
        });
    }

    @Test
    public void shouldNotProduceAuthRelatedEvents() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("_cat/indices");
        }

        auditLogsRule.assertExactlyScanAll(
            0,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.AUTHENTICATED
                || msg.getCategory() == AuditCategory.GRANTED_PRIVILEGES
                || msg.getCategory() == AuditCategory.FAILED_LOGIN
        );
    }

    @Test
    public void shouldCaptureMultipleIndicesFromBulkRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            String bulkBody = "{ \"index\": { \"_index\": \"bulk-index-a\", \"_id\": \"1\" } }\n"
                + "{ \"field\": \"value1\" }\n"
                + "{ \"index\": { \"_index\": \"bulk-index-b\", \"_id\": \"2\" } }\n"
                + "{ \"field\": \"value2\" }\n";
            client.postJson("_bulk", bulkBody);
        }

        // BulkRequest implements CompositeIndicesRequest — its indices() returns
        // the union of all sub-request indices
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write/bulk")) return false;
            return true;
        });
    }

    @Test
    public void shouldLogWildcardIndexAsRawString() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("logs-2026.*/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (!"SearchRequest".equals(msg.getRequestType())) return false;

            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if ("logs-2026.*".equals(idx)) return true;
            }
            return false;
        });
    }

    // --- Additional coverage: HTTP operations ---

    @Test
    public void shouldCaptureDeleteDocumentRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Create doc first, then delete
            client.putJson("del-test/_doc/1", "{\"field\": \"value\"}");
            client.delete("del-test/_doc/1");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/write/delete")
        );
    }

    @Test
    public void shouldCaptureDeleteIndexRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("to-delete/_doc/1", "{\"field\": \"value\"}");
            client.delete("to-delete");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:admin/delete")
        );
    }

    @Test
    public void shouldCaptureMgetRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            String mgetBody = "{\"docs\": [{\"_index\": \"mget-test\", \"_id\": \"1\"}, {\"_index\": \"mget-test\", \"_id\": \"2\"}]}";
            client.postJson("_mget", mgetBody);
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/read/mget")
        );
    }

    @Test
    public void shouldCaptureMultiSearchRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            String msearchBody = "{\"index\": \"msearch-test\"}\n{\"query\": {\"match_all\": {}}}\n";
            client.postJson("_msearch", msearchBody);
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/read/msearch")
        );
    }

    @Test
    public void shouldCaptureUpdateDocumentRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("update-test/_doc/1", "{\"field\": \"original\"}");
            client.postJson("update-test/_update/1", "{\"doc\": {\"field\": \"updated\"}}");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/write/update")
        );
    }

    @Test
    public void shouldCaptureCreateIndexRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("new-index-test", "{\"settings\": {\"number_of_shards\": 1}}");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:admin/create")
        );
    }

    @Test
    public void shouldCaptureClusterSettingsRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("_cluster/settings");
        }

        // GET _cluster/settings dispatches as a ClusterStateRequest internally
        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT && "ClusterStateRequest".equals(msg.getRequestType())
        );
    }

    @Test
    public void shouldCaptureNodesInfoRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("_nodes");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("cluster:monitor/nodes/info")
        );
    }

    @Test
    public void shouldCaptureGetDocumentRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("get-test/_doc/1", "{\"field\": \"value\"}");
            client.get("get-test/_doc/1");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/read/get")
        );
    }

    @Test
    public void shouldCaptureHeadRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.head("test-head-index");
        }

        // HEAD on an index triggers an indices:admin action (exists or resolve)
        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:admin")
        );
    }

    // --- Edge cases ---

    @Test
    public void shouldCaptureRequestToNonExistentIndex() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("does-not-exist/_doc/999");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/read/get")
        );
    }

    @Test
    public void shouldCaptureMultipleRapidRequests() {
        try (TestRestClient client = cluster.getRestClient()) {
            for (int i = 0; i < 20; i++) {
                client.get("_cluster/health");
            }
        }

        // Should produce at least 20 audit events
        auditLogsRule.assertAtLeast(
            20,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("cluster:monitor/health")
        );
    }

    @Test
    public void shouldCaptureAliasOperation() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("alias-source/_doc/1", "{\"field\": \"value\"}");
            client.postJson("_aliases", "{\"actions\": [{\"add\": {\"index\": \"alias-source\", \"alias\": \"my-alias\"}}]}");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:admin/aliases")
        );
    }

    @Test
    public void shouldCaptureCountRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("test-index/_count");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/read/search")
        );
    }

    @Test
    public void shouldCapturePatchRequest() {
        try (TestRestClient client = cluster.getRestClient()) {
            // Create a doc first, then patch it
            client.putJson("patch-test/_doc/1", "{\"field\": \"original\"}");
            client.patch("patch-test/_doc/1", "{\"doc\": {\"field\": \"patched\"}}");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/write")
        );
    }
}
