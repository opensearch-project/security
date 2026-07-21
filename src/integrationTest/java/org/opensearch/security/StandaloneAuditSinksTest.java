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
import java.util.concurrent.TimeUnit;

import org.awaitility.Awaitility;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.Matchers.containsString;

/**
 * Integration tests verifying that real audit sinks (internal_opensearch, log4j)
 * work end-to-end in standalone SSL-only mode.
 *
 * <p>Webhook sink delivery is verified at the unit level by {@code WebhookAuditLogTest}
 * (shared with FGAC). The integration test {@code StandaloneAuditWebhookSinkTest}
 * verifies the sink initializes without error in SSL-only mode.
 */
public class StandaloneAuditSinksTest {

    // --- Clusters ---

    @ClassRule
    public static LocalCluster internalSinkCluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(Map.of(ConfigConstants.SECURITY_SSL_ONLY, true, "plugins.security.audit.type", "internal_opensearch"))
        .sslOnly(true)
        .build();

    @ClassRule
    public static LocalCluster log4jSinkCluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_SSL_ONLY,
                true,
                "plugins.security.audit.type",
                "log4j",
                "plugins.security.audit.config.log4j.logger_name",
                "audit_standalone_test",
                "plugins.security.audit.config.log4j.level",
                "INFO"
            )
        )
        .sslOnly(true)
        .build();

    // --- Tests ---

    @Test
    public void internalOpenSearchSinkShouldCreateAuditIndex() {
        try (TestRestClient client = internalSinkCluster.getRestClient()) {
            client.get("_cluster/health");
        }

        try (TestRestClient client = internalSinkCluster.getRestClient()) {
            Awaitility.await()
                .alias("Audit index created with REQUEST_AUDIT events")
                .atMost(10, TimeUnit.SECONDS)
                .pollInterval(1, TimeUnit.SECONDS)
                .until(() -> client.get("security-auditlog-*/_search").getBody(), containsString("REQUEST_AUDIT"));
        }
    }

    @Test
    public void internalOpenSearchSinkShouldCaptureCorrectFields() {
        try (TestRestClient client = internalSinkCluster.getRestClient()) {
            client.get("test-index/_search");
        }

        try (TestRestClient client = internalSinkCluster.getRestClient()) {
            Awaitility.await()
                .alias("Audit event has expected fields")
                .atMost(10, TimeUnit.SECONDS)
                .pollInterval(1, TimeUnit.SECONDS)
                .until(
                    () -> client.get("security-auditlog-*/_search?q=audit_transport_request_type:SearchRequest").getBody(),
                    containsString("audit_request_privilege")
                );
        }
    }

    @Test
    public void log4jSinkShouldNotCrashAndProcessRequests() {
        // Log4j sink writes to a Log4j logger — we can't easily capture the output
        // in an integration test. But we CAN verify the cluster boots with log4j sink
        // configured and requests succeed without errors (proving the sink initializes
        // and processes messages without throwing).
        try (TestRestClient client = log4jSinkCluster.getRestClient()) {
            TestRestClient.HttpResponse response = client.get("_cluster/health");
            response.assertStatusCode(200);
        }

        // Send multiple requests to ensure no backpressure or queue issues
        try (TestRestClient client = log4jSinkCluster.getRestClient()) {
            for (int i = 0; i < 10; i++) {
                client.get("_cat/indices");
            }
            TestRestClient.HttpResponse response = client.get("_cluster/health");
            response.assertStatusCode(200);
        }
    }
}
