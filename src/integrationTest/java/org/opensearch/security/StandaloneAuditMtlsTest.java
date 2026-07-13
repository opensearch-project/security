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
}
