/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security;

import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.awaitility.Awaitility.await;
import static org.junit.Assert.assertEquals;

/**
 * Test related to SSL-only mode of security plugin. In this mode, the security plugin is responsible only for TLS/SSL encryption.
 * Therefore, the plugin does not perform authentication and authorization. Moreover, the REST resources (e.g. /_plugins/_security/whoami,
 * /_plugins/_security/authinfo, etc.) provided by the plugin are not available.
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class EncryptionInTransitMigrationTests {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.DEFAULT)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(Map.of(ConfigConstants.SECURITY_SSL_ONLY, true))
        .sslOnly(true)
        .nodeSpecificSettings(0, Map.of(ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, true))
        .nodeSpecificSettings(1, Map.of(ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, true))
        .extectedNodeStartupCount(2)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .build();

    @Test
    public void shouldOnlyConnectWithThirdNodeAfterDynamicDualModeChange() {
        try (TestRestClient client = cluster.getRestClient()) {
            TestRestClient.HttpResponse response = client.get("_cat/nodes");
            response.assertStatusCode(200);

            String[] lines = response.getBody().split("\n");
            assertEquals("Expected 2 nodes in the initial response", 2, lines.length);

            String settingsJson = "{\"persistent\": {\"plugins.security_config.ssl_dual_mode_enabled\": false}}";
            TestRestClient.HttpResponse settingsResponse = client.putJson("_cluster/settings", settingsJson);
            settingsResponse.assertStatusCode(200);

            await().atMost(10, SECONDS).pollInterval(1, SECONDS).until(() -> {
                TestRestClient.HttpResponse secondResponse = client.get("_cat/nodes");
                String[] secondLines = secondResponse.getBody().split("\n");
                return secondLines.length == 3;
            });
        }
    }
}
