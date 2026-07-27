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

import org.junit.After;
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
 * Integration test verifying that client certificate CN/SAN is captured
 * as effective_user in audit events when mTLS is configured in SSL-only mode.
 */
public class StandaloneAuditMtlsTest {

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
                "plugins.security.ssl.http.clientauth_mode",
                "OPTIONAL"
            )
        )
        .sslOnly(true)
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @After
    public void resetIgnoreUsers() {
        try (TestRestClient client = cluster.getRestClient(cluster.getTestCertificates().getAdminCertificateData())) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.ignore_users\": []}}");
        }
    }

    @Test
    public void shouldCaptureClientCertPrincipalAsEffectiveUser() {
        // Send request with the admin client certificate
        try (TestRestClient client = cluster.getRestClient(cluster.getTestCertificates().getAdminCertificateData())) {
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            // The admin cert DN should appear as effective_user
            String user = msg.getEffectiveUser();
            return user != null && user.contains("CN=kirk");
        });
    }

    @Test
    public void shouldSuppressEventsWhenCertDnAddedToIgnoreUsersAtRuntime() {
        // Step 1: Verify events WITH cert user ARE produced BEFORE ignore
        try (TestRestClient client = cluster.getRestClient(cluster.getTestCertificates().getAdminCertificateData())) {
            client.putJson("mtls-before-ignore/_doc/1?refresh=true", "{\"data\": \"before-ignore\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getEffectiveUser() == null || !msg.getEffectiveUser().contains("CN=kirk")) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if ("mtls-before-ignore".equals(idx)) return true;
            }
            return false;
        });

        // Step 2: Dynamically add cert DN to ignore_users
        try (TestRestClient client = cluster.getRestClient(cluster.getTestCertificates().getAdminCertificateData())) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.ignore_users\": [\"*kirk*\"]}}");
        }

        auditLogsRule.waitForAuditLogs();

        // Step 3: Send request that should be suppressed
        try (TestRestClient client = cluster.getRestClient(cluster.getTestCertificates().getAdminCertificateData())) {
            client.putJson("mtls-after-ignore/_doc/1?refresh=true", "{\"data\": \"should-not-appear\"}");
        }

        // Assert: no user-originated events for the AFTER index
        auditLogsRule.waitForAuditLogs();
        auditLogsRule.assertExactlyScanAll(0, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.REQUEST_AUDIT) return false;
            if (msg.getEffectiveUser() == null) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object indices = fields.get(AuditMessage.INDICES);
            if (indices == null) return false;
            String[] indexArr = (String[]) indices;
            for (String idx : indexArr) {
                if ("mtls-after-ignore".equals(idx)) return true;
            }
            return false;
        });

        // Reset
        try (TestRestClient client = cluster.getRestClient(cluster.getTestCertificates().getAdminCertificateData())) {
            client.putJson("_cluster/settings", "{\"persistent\": {\"plugins.security.audit.config.ignore_users\": []}}");
        }
    }
}
