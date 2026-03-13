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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.Rule;
import org.junit.Test;

import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.log.LogCapturingAppender;
import org.opensearch.test.framework.log.LogsRule;

import static java.util.concurrent.Executors.newSingleThreadExecutor;
import static org.awaitility.Awaitility.await;

public class TlsHostnameVerificationTests {

    @Rule
    public LogsRule logsRule = new LogsRule("org.opensearch.transport.netty4.ssl.SecureNetty4Transport");

    public LocalCluster.Builder clusterBuilder = new LocalCluster.Builder().clusterManager(ClusterManager.DEFAULT)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of("plugins.security.ssl_only", true, "transport.ssl.enforce_hostname_verification", true, "cluster.join.timeout", "10s")
        )
        .sslOnly(true);

    @Test
    public void clusterShouldStart_nodesSanIpsAreValid() {
        // Note: We cannot use hostnames in this environment. However, IP addresses also work as valid SANs which are also
        // subject to hostname verification. Thus, we use here certificates with IP SANs
        TestCertificates testCertificates = new TestCertificates(ClusterManager.DEFAULT.getNodes(), "127.0.0.1");
        try (LocalCluster cluster = clusterBuilder.testCertificates(testCertificates).build()) {
            cluster.before();
        }
    }

    @Test
    public void clusterShouldNotStart_nodesSanIpsAreInvalid() {
        TestCertificates testCertificates = new TestCertificates(ClusterManager.DEFAULT.getNodes(), "127.0.0.2");
        try (
            LocalCluster cluster = clusterBuilder.testCertificates(testCertificates).build();
            ExecutorService executorService = newSingleThreadExecutor()
        ) {
            Future<Void> clusterFuture = executorService.submit(() -> {
                cluster.before();
                return null;
            });
            await().alias("expect error message about hostname verification")
                .pollDelay(10, TimeUnit.MILLISECONDS)
                .until(
                    () -> LogCapturingAppender.getLogMessagesAsString()
                        .stream()
                        .anyMatch(
                            message -> message.contains("(certificate_unknown) No subject alternative names matching IP address 127.0.0.1")
                        )
                );
            clusterFuture.cancel(true);
        } catch (Exception e) {
            logsRule.assertThatContain("No subject alternative names matching IP address 127.0.0.1 found");
        }
    }
}
