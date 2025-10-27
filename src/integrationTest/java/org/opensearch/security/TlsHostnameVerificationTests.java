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
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.log.LogsRule;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class TlsHostnameVerificationTests {

    @Rule
    public LogsRule logsRule = new LogsRule("org.opensearch.transport.netty4.ssl.SecureNetty4Transport");

    public LocalCluster.Builder clusterBuilder = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(
            Map.of(ConfigConstants.SECURITY_SSL_ONLY, true, SSLConfigConstants.TRANSPORT_SSL_ENFORCE_HOSTNAME_VERIFICATION_KEY, true)
        )
        .sslOnly(true);

    @Test
    public void clusterShouldStart_nodesSanIpsAreValid() {
        // Note: We cannot use hostnames in this environment. However, IP addresses also work as valid SANs which are also
        // subject to hostname verification. Thus, we use here certificates with IP SANs
        TestCertificates testCertificates = new TestCertificates(ClusterManager.THREE_CLUSTER_MANAGERS.getNodes(), "127.0.0.1");
        try (LocalCluster cluster = clusterBuilder.testCertificates(testCertificates).build()) {
            cluster.before();
        } catch (Exception e) {
            Assert.fail("Cluster should start, no exception expected but got: " + e.getMessage());
        }
    }

    @Test
    public void clusterShouldNotStart_nodesSanIpsAreInvalid() {
        TestCertificates testCertificates = new TestCertificates(ClusterManager.THREE_CLUSTER_MANAGERS.getNodes(), "127.0.0.2");
        try (LocalCluster cluster = clusterBuilder.testCertificates(testCertificates).build()) {
            cluster.before();
            Assert.fail("Cluster should not start, an exception expected");
        } catch (Exception e) {
            logsRule.assertThatContain("No subject alternative names matching IP address 127.0.0.1 found");
        }
    }
}
