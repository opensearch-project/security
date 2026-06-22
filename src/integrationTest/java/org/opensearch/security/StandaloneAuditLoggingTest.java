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
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

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
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY, true,
                "plugins.security.audit.type", TestRuleAuditLogSink.class.getName()
            )
        )
        .sslOnly(true)
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void shouldProduceRequestAuditEventForSearch() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("test-index/_search");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && "SearchRequest".equals(msg.getRequestType())
        );
    }

    @Test
    public void shouldProduceRequestAuditEventForIndexOperation() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.putJson("test-index/_doc/1", "{\"field\": \"value\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("indices:data/write")
        );
    }

    @Test
    public void shouldProduceRequestAuditEventForClusterHealth() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.REQUEST_AUDIT
                && msg.getPrivilege() != null
                && msg.getPrivilege().contains("cluster:monitor/health")
        );
    }

    @Test
    public void shouldNotProduceAuthRelatedEvents() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("_cat/indices");
        }

        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) ->
            msg.getCategory() == AuditCategory.AUTHENTICATED
                || msg.getCategory() == AuditCategory.GRANTED_PRIVILEGES
                || msg.getCategory() == AuditCategory.FAILED_LOGIN
        );
    }
}
