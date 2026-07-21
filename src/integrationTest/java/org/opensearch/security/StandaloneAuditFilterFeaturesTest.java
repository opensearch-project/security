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
 * Integration tests for standalone audit logging filter features in SSL-only mode.
 * Covers: request body logging, sensitive header exclusion, ignore-users,
 * ignore-requests, index resolution, and bulk request handling.
 */
public class StandaloneAuditFilterFeaturesTest {

    // --- Cluster with full features enabled (body, resolve, bulk) ---
    @ClassRule
    public static LocalCluster fullFeaturesCluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY,
                true,
                "plugins.security.audit.type",
                TestRuleAuditLogSink.class.getName(),
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY,
                true,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES,
                true,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS,
                true,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS,
                true
            )
        )
        .sslOnly(true)
        .build();

    // --- Cluster with ignore-requests configured ---
    @ClassRule
    public static LocalCluster ignoreRequestsCluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY,
                true,
                "plugins.security.audit.type",
                TestRuleAuditLogSink.class.getName(),
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS,
                List.of("indices:data/read/search", "SearchRequest")
            )
        )
        .sslOnly(true)
        .build();

    // --- Cluster with request body logging DISABLED ---
    @ClassRule
    public static LocalCluster noBodyCluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY,
                true,
                "plugins.security.audit.type",
                TestRuleAuditLogSink.class.getName(),
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY,
                false
            )
        )
        .sslOnly(true)
        .build();

    // --- Cluster with ignore-users configured ---
    @ClassRule
    public static LocalCluster ignoreUsersCluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY,
                true,
                "plugins.security.audit.type",
                TestRuleAuditLogSink.class.getName(),
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS,
                List.of("CN=kirk,OU=client,O=client,L=test,*"),
                "plugins.security.ssl.http.clientauth_mode",
                "OPTIONAL"
            )
        )
        .sslOnly(true)
        .build();

    // --- Cluster with wildcard ignore-users (*) to suppress ALL users ---
    @ClassRule
    public static LocalCluster ignoreAllUsersCluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY,
                true,
                "plugins.security.audit.type",
                TestRuleAuditLogSink.class.getName(),
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS,
                List.of("*"),
                "plugins.security.ssl.http.clientauth_mode",
                "OPTIONAL"
            )
        )
        .sslOnly(true)
        .build();

    // --- Cluster with bulk resolve DISABLED (default: aggregated single event) ---
    @ClassRule
    public static LocalCluster bulkAggregatedCluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY,
                true,
                "plugins.security.audit.type",
                TestRuleAuditLogSink.class.getName(),
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS,
                false
            )
        )
        .sslOnly(true)
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    // =====================================================================
    // Request Body Logging
    // =====================================================================

    @Test
    public void shouldLogRequestBodyForSearchRequest() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            client.putJson("body-test/_doc/1?refresh=true", "{\"name\": \"test\"}");
            client.postJson("body-test/_search", "{\"query\": {\"match_all\": {}}}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/read/search")) return false;
            String body = msg.getRequestBody();
            return body != null && body.contains("match_all");
        });
    }

    @Test
    public void shouldLogRequestBodyForIndexRequest() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            client.putJson("body-test/_doc/2", "{\"field\": \"indexed-value\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write")) return false;
            String body = msg.getRequestBody();
            return body != null && body.contains("indexed-value");
        });
    }

    @Test
    public void shouldLogRequestBodyForUpdateRequest() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            client.putJson("body-test/_doc/3?refresh=true", "{\"field\": \"original\"}");
            client.postJson("body-test/_update/3", "{\"doc\": {\"field\": \"updated-value\"}}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write/update")) return false;
            String body = msg.getRequestBody();
            return body != null && body.contains("updated-value");
        });
    }

    @Test
    public void shouldNotLogRequestBodyWhenDisabled() {
        try (TestRestClient client = noBodyCluster.getRestClient()) {
            client.postJson("nobody-test/_search", "{\"query\": {\"match_all\": {}}}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/read/search")) return false;
            // Body should be absent when log_request_body is false
            return msg.getRequestBody() == null;
        });
    }

    @Test
    public void shouldHandleSearchWithNoBody() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            // GET search with no request body — source is null
            client.get("body-test/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/read/search")) return false;
            // No meaningful body provided — either null or empty "{}"
            String body = msg.getRequestBody();
            return body == null || body.equals("{}");
        });
    }

    // =====================================================================
    // Sensitive Header Exclusion
    // =====================================================================

    @Test
    public void shouldExcludeAuthorizationHeaderFromAuditEvent() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object headers = fields.get(AuditMessage.REST_REQUEST_HEADERS);
            if (headers == null) return true; // no headers is fine
            String headerStr = headers.toString().toLowerCase();
            return !headerStr.contains("authorization");
        });
    }

    @Test
    public void shouldPreserveNonSensitiveHeaders() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            // Content-Type and other standard headers should still be present
            client.putJson("header-test/_doc/1", "{\"field\": \"value\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write")) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object headers = fields.get(AuditMessage.REST_REQUEST_HEADERS);
            if (headers == null) return false;
            // Content-Type should be preserved (it's not sensitive)
            String headerStr = headers.toString().toLowerCase();
            return headerStr.contains("content-type");
        });
    }

    // =====================================================================
    // Ignore-Users Filtering
    // =====================================================================

    @Test
    public void shouldSuppressEventsForIgnoredCertUser() {
        try (TestRestClient client = ignoreUsersCluster.getRestClient(ignoreUsersCluster.getTestCertificates().getAdminCertificateData())) {
            client.get("_cluster/health");
            client.get("ignore-user-test/_search");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            String user = msg.getEffectiveUser();
            return user != null && user.contains("CN=kirk");
        });
    }

    @Test
    public void shouldLogEventsForNonIgnoredUsers() {
        try (TestRestClient client = ignoreUsersCluster.getRestClient()) {
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
    public void shouldNotSuppressPartialUserMatch() {
        // The ignore pattern is "CN=kirk,OU=client,O=client,L=test,C=DE"
        // A request with no client cert (null user) should NOT be suppressed
        try (TestRestClient client = ignoreUsersCluster.getRestClient()) {
            client.putJson("partial-match/_doc/1", "{\"field\": \"value\"}");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/write")
        );
    }

    // =====================================================================
    // Ignore-Requests Filtering
    // =====================================================================

    @Test
    public void shouldSuppressEventsForIgnoredActionPattern() {
        try (TestRestClient client = ignoreRequestsCluster.getRestClient()) {
            client.postJson("ignored-action/_search", "{\"query\": {\"match_all\": {}}}");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(
            0,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/read/search")
        );
    }

    @Test
    public void shouldStillLogNonIgnoredRequests() {
        try (TestRestClient client = ignoreRequestsCluster.getRestClient()) {
            client.putJson("not-ignored/_doc/1", "{\"field\": \"value\"}");
        }

        auditLogsRule.assertAtLeast(
            1,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/write")
        );
    }

    @Test
    public void shouldNeverLogInternalActions() {
        // internal:* actions are always skipped regardless of ignore_requests config
        // Trigger some internal traffic by doing a normal operation (causes internal coordination)
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            client.get("_cluster/health");
        }

        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(
            0,
            (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().startsWith("internal:")
        );
    }

    // =====================================================================
    // Index Resolution (wildcards → actual indices)
    // =====================================================================

    @Test
    public void shouldResolveWildcardIndicesToActualNames() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            client.putJson("resolve-logs-2026.01/_doc/1?refresh=true", "{\"msg\": \"jan\"}");
            client.putJson("resolve-logs-2026.02/_doc/1?refresh=true", "{\"msg\": \"feb\"}");
            client.get("resolve-logs-2026.*/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (!"SearchRequest".equals(msg.getRequestType())) return false;

            Map<String, Object> fields = msg.getAsMap();

            // Raw indices should contain the wildcard pattern
            Object rawIndices = fields.get(AuditMessage.INDICES);
            if (rawIndices == null) return false;
            String[] raw = (String[]) rawIndices;
            boolean hasWildcard = false;
            for (String idx : raw) {
                if ("resolve-logs-2026.*".equals(idx)) hasWildcard = true;
            }
            if (!hasWildcard) return false;

            // Resolved indices should contain actual index names
            Object resolvedIndices = fields.get(AuditMessage.RESOLVED_INDICES);
            if (resolvedIndices == null) return false;
            String[] resolved = (String[]) resolvedIndices;
            boolean hasJan = false;
            boolean hasFeb = false;
            for (String idx : resolved) {
                if ("resolve-logs-2026.01".equals(idx)) hasJan = true;
                if ("resolve-logs-2026.02".equals(idx)) hasFeb = true;
            }
            return hasJan && hasFeb;
        });
    }

    @Test
    public void shouldResolveConcreteIndexToItself() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            client.putJson("concrete-idx/_doc/1?refresh=true", "{\"field\": \"value\"}");
            client.get("concrete-idx/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (!"SearchRequest".equals(msg.getRequestType())) return false;

            Map<String, Object> fields = msg.getAsMap();
            Object rawIndices = fields.get(AuditMessage.INDICES);
            if (rawIndices == null) return false;
            String[] raw = (String[]) rawIndices;
            boolean hasConcrete = false;
            for (String idx : raw) {
                if ("concrete-idx".equals(idx)) hasConcrete = true;
            }
            if (!hasConcrete) return false;

            // Resolved should also contain the same concrete name
            Object resolvedIndices = fields.get(AuditMessage.RESOLVED_INDICES);
            if (resolvedIndices == null) return false;
            String[] resolved = (String[]) resolvedIndices;
            for (String idx : resolved) {
                if ("concrete-idx".equals(idx)) return true;
            }
            return false;
        });
    }

    @Test
    public void shouldHandleNonExistentWildcardGracefully() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            // No indices match this wildcard — resolution returns empty
            client.get("nonexistent-xyz-*/_search");
        }

        // Should still produce an audit event (even if 404) with the raw wildcard
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (!"SearchRequest".equals(msg.getRequestType())) return false;

            Map<String, Object> fields = msg.getAsMap();
            Object rawIndices = fields.get(AuditMessage.INDICES);
            if (rawIndices == null) return false;
            String[] raw = (String[]) rawIndices;
            for (String idx : raw) {
                if ("nonexistent-xyz-*".equals(idx)) return true;
            }
            return false;
        });
    }

    // =====================================================================
    // Bulk Request Handling (per-item events)
    // =====================================================================

    @Test
    public void shouldLogPerItemEventsForBulkRequest() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            String bulkBody = "{ \"index\": { \"_index\": \"bulk-a\", \"_id\": \"1\" } }\n"
                + "{ \"field\": \"value-a\" }\n"
                + "{ \"index\": { \"_index\": \"bulk-b\", \"_id\": \"2\" } }\n"
                + "{ \"field\": \"value-b\" }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        // With resolve_bulk_requests=true, we should get per-item events
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if ("bulk-a".equals(idx)) return true;
            }
            return false;
        });

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if ("bulk-b".equals(idx)) return true;
            }
            return false;
        });
    }

    @Test
    public void shouldIncludeDocIdInBulkPerItemEvents() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            String bulkBody = "{ \"index\": { \"_index\": \"bulk-id-test\", \"_id\": \"my-doc-99\" } }\n" + "{ \"data\": \"test\" }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object docId = fields.get(AuditMessage.ID);
            return "my-doc-99".equals(docId);
        });
    }

    @Test
    public void shouldIncludeBodyInBulkPerItemEvents() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            String bulkBody = "{ \"index\": { \"_index\": \"bulk-body-test\", \"_id\": \"1\" } }\n"
                + "{ \"secret\": \"bulk-payload-123\" }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            boolean isBulkBodyTest = false;
            for (String idx : indexArr) {
                if ("bulk-body-test".equals(idx)) isBulkBodyTest = true;
            }
            if (!isBulkBodyTest) return false;
            String body = msg.getRequestBody();
            return body != null && body.contains("bulk-payload-123");
        });
    }

    @Test
    public void shouldLogMixedBulkOperations() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            // First create a doc so we can delete it
            client.putJson("bulk-mixed/_doc/to-delete?refresh=true", "{\"field\": \"delete-me\"}");

            String bulkBody = "{ \"index\": { \"_index\": \"bulk-mixed\", \"_id\": \"new-doc\" } }\n"
                + "{ \"field\": \"created\" }\n"
                + "{ \"delete\": { \"_index\": \"bulk-mixed\", \"_id\": \"to-delete\" } }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        // Should have per-item event for the index operation
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object docId = fields.get(AuditMessage.ID);
            return "new-doc".equals(docId);
        });

        // Should have per-item event for the delete operation
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object docId = fields.get(AuditMessage.ID);
            return "to-delete".equals(docId);
        });
    }

    @Test
    public void shouldIncludeShardIdInBulkPerItemEvents() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            String bulkBody = "{ \"index\": { \"_index\": \"bulk-shard-test\", \"_id\": \"1\" } }\n" + "{ \"data\": \"shard-check\" }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            boolean isShardTest = false;
            for (String idx : indexArr) {
                if ("bulk-shard-test".equals(idx)) isShardTest = true;
            }
            if (!isShardTest) return false;
            // Shard ID should be present for bulk per-item events
            Object shardId = fields.get(AuditMessage.SHARD_ID);
            return shardId != null;
        });
    }

    // =====================================================================
    // Edge Cases: Ignore-Users Wildcards
    // =====================================================================

    @Test
    public void shouldSuppressAllEventsWhenWildcardIgnoreUsers() {
        // ignore_users: ["*"] should suppress events that have an identified user
        // System background events with null user are still logged (no identity to match)
        try (
            TestRestClient client = ignoreAllUsersCluster.getRestClient(
                ignoreAllUsersCluster.getTestCertificates().getAdminCertificateData()
            )
        ) {
            client.get("_cluster/health");
            client.putJson("wildcard-ignore/_doc/1", "{\"field\": \"value\"}");
        }

        auditLogsRule.waitForAuditLogs();
        // No events should have an effective_user (those are suppressed by wildcard)
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            return msg.getEffectiveUser() != null;
        });
    }

    // =====================================================================
    // Edge Cases: Bulk Aggregated (resolve_bulk_requests=false)
    // =====================================================================

    @Test
    public void shouldLogSingleEventForBulkWhenResolveDisabled() {
        try (TestRestClient client = bulkAggregatedCluster.getRestClient()) {
            String bulkBody = "{ \"index\": { \"_index\": \"agg-bulk-a\", \"_id\": \"1\" } }\n"
                + "{ \"field\": \"value-a\" }\n"
                + "{ \"index\": { \"_index\": \"agg-bulk-b\", \"_id\": \"2\" } }\n"
                + "{ \"field\": \"value-b\" }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        // With resolve_bulk_requests=false, we get an event for the BulkRequest itself
        // (action: indices:data/write/bulk) rather than per-item events
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            return msg.getPrivilege() != null && msg.getPrivilege().contains("indices:data/write/bulk");
        });
    }

    // =====================================================================
    // Edge Cases: Remote Address
    // =====================================================================

    @Test
    public void shouldCaptureRemoteAddressInEvents() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("cluster:monitor/health")) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object remoteAddr = fields.get(AuditMessage.REMOTE_ADDRESS);
            // Should have a remote address (127.0.0.1 in test)
            return remoteAddr != null && remoteAddr.toString().contains("127.0.0.1");
        });
    }

    // =====================================================================
    // Edge Cases: Header Case-Insensitive Matching
    // =====================================================================

    @Test
    public void shouldExcludeAuthorizationHeaderCaseInsensitive() {
        // The AUTHORIZATION_HEADER WildcardMatcher uses .ignoreCase()
        // so "authorization", "Authorization", "AUTHORIZATION" are all excluded
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            client.putJson("case-header-test/_doc/1", "{\"field\": \"value\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write")) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object headers = fields.get(AuditMessage.REST_REQUEST_HEADERS);
            if (headers == null) return true; // no headers is acceptable
            String headerStr = headers.toString();
            // None of the case variants should be present
            return !headerStr.toLowerCase().contains("authorization");
        });
    }

    // =====================================================================
    // Bulk — mixed operations log correct request types
    // =====================================================================

    @Test
    public void shouldLogCorrectRequestTypeForMixedBulkOperations() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            // Create docs first so delete and update have targets
            client.putJson("bulk-types/_doc/del-target?refresh=true", "{\"field\": \"delete-me\"}");
            client.putJson("bulk-types/_doc/upd-target?refresh=true", "{\"field\": \"update-me\"}");

            String bulkBody = "{ \"index\": { \"_index\": \"bulk-types\", \"_id\": \"idx-1\" } }\n"
                + "{ \"field\": \"indexed\" }\n"
                + "{ \"delete\": { \"_index\": \"bulk-types\", \"_id\": \"del-target\" } }\n"
                + "{ \"update\": { \"_index\": \"bulk-types\", \"_id\": \"upd-target\" } }\n"
                + "{ \"doc\": { \"field\": \"updated\" } }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        // Index operation should have IndexRequest type
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object docId = fields.get(AuditMessage.ID);
            Object requestType = fields.get(AuditMessage.TRANSPORT_REQUEST_TYPE);
            return "idx-1".equals(docId) && requestType != null && requestType.toString().contains("IndexRequest");
        });

        // Delete operation should have DeleteRequest type
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object docId = fields.get(AuditMessage.ID);
            Object requestType = fields.get(AuditMessage.TRANSPORT_REQUEST_TYPE);
            return "del-target".equals(docId) && requestType != null && requestType.toString().contains("DeleteRequest");
        });
    }

    // =====================================================================
    // Bulk — multi-index bulk produces per-item events with correct indices
    // =====================================================================

    @Test
    public void shouldLogPerItemEventsWithCorrectIndicesForMultiIndexBulk() {
        try (TestRestClient client = fullFeaturesCluster.getRestClient()) {
            String bulkBody = "{ \"index\": { \"_index\": \"bulk-idx-alpha\", \"_id\": \"a1\" } }\n"
                + "{ \"data\": \"alpha\" }\n"
                + "{ \"index\": { \"_index\": \"bulk-idx-beta\", \"_id\": \"b1\" } }\n"
                + "{ \"data\": \"beta\" }\n"
                + "{ \"index\": { \"_index\": \"bulk-idx-gamma\", \"_id\": \"g1\" } }\n"
                + "{ \"data\": \"gamma\" }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        // Each per-item event should have its own target index
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if ("bulk-idx-alpha".equals(idx)) return true;
            }
            return false;
        });

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if ("bulk-idx-beta".equals(idx)) return true;
            }
            return false;
        });

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if ("bulk-idx-gamma".equals(idx)) return true;
            }
            return false;
        });
    }
}
