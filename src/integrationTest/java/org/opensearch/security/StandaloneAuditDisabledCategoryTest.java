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
 * Integration test verifying that the unified disabled_categories setting
 * suppresses REQUEST_AUDIT events end-to-end in SSL-only mode.
 */
public class StandaloneAuditDisabledCategoryTest {

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
                ConfigConstants.SECURITY_AUDIT_CONFIG_DISABLED_CATEGORIES,
                List.of("REQUEST_AUDIT")
            )
        )
        .sslOnly(true)
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void shouldSuppressEventsWhenRequestAuditIsDisabled() {
        try (TestRestClient client = cluster.getRestClient()) {
            client.get("_cluster/health");
            client.get("test-index/_search");
        }

        // Wait then assert no REQUEST_AUDIT events were produced
        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT);
    }

    // --- Cluster with REQUEST_AUDIT disabled via disabled_rest_categories only ---
    @ClassRule
    public static LocalCluster restCategoryCluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY,
                true,
                "plugins.security.audit.type",
                TestRuleAuditLogSink.class.getName(),
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
                List.of("REQUEST_AUDIT")
            )
        )
        .sslOnly(true)
        .build();

    @Test
    public void shouldSuppressEventsWhenRequestAuditIsDisabledViaRestCategories() {
        try (TestRestClient client = restCategoryCluster.getRestClient()) {
            client.get("_cluster/health");
            client.putJson("rest-cat-test/_doc/1?refresh=true", "{\"field\": \"value\"}");
        }

        // Wait then assert no REQUEST_AUDIT events were produced
        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> msg.getCategory() == AuditCategory.REQUEST_AUDIT);
    }
}
