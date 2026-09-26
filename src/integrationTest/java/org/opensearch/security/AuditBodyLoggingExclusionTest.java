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
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.audit.TestRuleAuditLogSink;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

/**
 * Integration tests for body logging exclusions feature.
 * Verifies that request bodies are excluded from audit events
 * when the action/path matches configured exclusion patterns.
 */
public class AuditBodyLoggingExclusionTest {

    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(
        new TestSecurityConfig.Role("all_access").clusterPermissions("*").indexPermissions("*").on("*")
    );

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .users(ADMIN_USER)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .nodeSettings(
            Map.of(
                // Audit sink type (required for node-level exclusion parsing)
                "plugins.security.audit.type",
                TestRuleAuditLogSink.class.getName(),
                // Define action groups
                "plugins.security.audit.config.action_groups.BULK",
                "indices:data/write/bulk*,/_bulk",
                "plugins.security.audit.config.action_groups.SEARCH",
                "indices:data/read/search*,/_search",
                // Exclude BULK from body logging
                "plugins.security.audit.config.body_logging_exclusions",
                "BULK"
            )
        )
        .audit(new AuditConfiguration(true).filters(new AuditFilters().enabledRest(true).enabledTransport(true)))
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void shouldExcludeBodyForBulkRequest() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            String bulkBody = "{ \"index\": { \"_index\": \"test-idx\", \"_id\": \"1\" } }\n" + "{ \"field\": \"value\" }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        // GRANTED_PRIVILEGES event for bulk should have NO body (excluded)
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.GRANTED_PRIVILEGES) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write/bulk")) return false;
            return msg.getRequestBody() == null;
        });
    }

    @Test
    public void shouldStillLogBodyForNonExcludedRequest() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.putJson("test-idx/_doc/1", "{\"field\": \"value\"}");
        }

        // Single index request is NOT excluded — body should be present
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.GRANTED_PRIVILEGES) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/write/index")) return false;
            String body = msg.getRequestBody();
            return body != null && body.contains("value");
        });
    }

    @Test
    public void shouldExcludeBodyOnRestPathForBulk() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            String bulkBody = "{ \"index\": { \"_index\": \"rest-test\", \"_id\": \"1\" } }\n" + "{ \"message\": \"hello\" }\n";
            client.postJson("_bulk", bulkBody);
        }

        // AUTHENTICATED event (REST path) should also have no body for /_bulk
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.AUTHENTICATED) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object path = fields.get(AuditMessage.REST_REQUEST_PATH);
            if (path == null || !path.toString().contains("_bulk")) return false;
            return msg.getRequestBody() == null;
        });
    }

    @Test
    public void shouldLogBodyForSearchWhenOnlyBulkExcluded() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.postJson("test-idx/_search", "{\"query\": {\"match_all\": {}}}");
        }

        // Search is NOT in the exclusion list — body should be logged
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.GRANTED_PRIVILEGES) return false;
            if (msg.getPrivilege() == null || !msg.getPrivilege().contains("indices:data/read/search")) return false;
            String body = msg.getRequestBody();
            return body != null && body.contains("match_all");
        });
    }

    @Test
    public void shouldMatchShardLevelActionWithWildcard() {
        // Bulk produces shard-level actions like "indices:data/write/bulk[s][p]"
        // Our pattern "indices:data/write/bulk*" should match it
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            String bulkBody = "{ \"index\": { \"_index\": \"shard-test\", \"_id\": \"1\" } }\n" + "{ \"field\": \"shard-level\" }\n";
            client.postJson("_bulk?refresh=true", bulkBody);
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.GRANTED_PRIVILEGES) return false;
            if (msg.getPrivilege() == null) return false;
            if (!msg.getPrivilege().contains("indices:data/write/bulk")) return false;
            // Body should be excluded even for shard-level bulk[s][p]
            return msg.getRequestBody() == null;
        });
    }
}
