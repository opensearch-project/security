/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.transport;

import java.security.cert.X509Certificate;
import java.util.Optional;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.plugins.PluginsService;
import org.opensearch.plugins.SecureTransportSettingsProvider;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.LocalOpenSearchCluster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

/**
 * Checks SecureTransportSettingsProvider.isNodeCertificate on a running node: the security plugin applies the
 * inter-cluster request evaluator of the node, with the node's own transport certificates as the local certificates.
 */
public class TransportNodeCertificateCheckTest {

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .build();

    @Test
    public void nodeCertificateIsANodeAndAdminCertificateIsNot() {
        final SecureTransportSettingsProvider provider = transportSettingsProvider(cluster.nodes().get(0));
        final X509Certificate node = cluster.getTestCertificates().getNodeCertificateData(0).certificate();
        final X509Certificate admin = cluster.getTestCertificates().getAdminCertificateData().certificate();

        assertThat(provider.isNodeCertificate(new X509Certificate[] { node }), is(Optional.of(true)));
        assertThat(provider.isNodeCertificate(new X509Certificate[] { admin }), is(Optional.of(false)));
    }

    private static SecureTransportSettingsProvider transportSettingsProvider(final LocalOpenSearchCluster.Node node) {
        final OpenSearchSecurityPlugin plugin = node.getInjectable(PluginsService.class)
            .filterPlugins(OpenSearchSecurityPlugin.class)
            .get(0);
        final Settings settings = node.getInjectable(ClusterService.class).getSettings();
        return plugin.getSecureSettingFactory(settings).orElseThrow().getSecureTransportSettingsProvider(settings).orElseThrow();
    }
}
