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

package org.opensearch.security;

import java.security.cert.X509Certificate;
import java.util.Optional;
import javax.security.auth.x500.X500Principal;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.ssl.transport.DefaultPrincipalExtractor;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.transport.DefaultInterClusterRequestEvaluator;
import org.opensearch.security.transport.InterClusterRequestEvaluator;
import org.opensearch.security.transport.OIDClusterRequestEvaluator;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OpenSearchSecurityPluginNodeCertificateTest {

    private static final String NODE_OID = "1.2.3.4.5.5";
    private static final String NODE_DN = "CN=node-0.example.com,OU=node,O=node,L=test,C=de";
    private static final Settings SETTINGS = Settings.builder()
        .put(ConfigConstants.SECURITY_CERT_OID, NODE_OID)
        .putList(ConfigConstants.SECURITY_NODES_DN, NODE_DN)
        .build();

    @Test
    public void emptyWithoutEvaluatorOrPeerChain() {
        final X509Certificate[] chain = { certificate(NODE_DN, null) };
        assertThat(isNodeCertificate(null, chain, chain), is(Optional.empty()));
        assertThat(isNodeCertificate(new OIDClusterRequestEvaluator(SETTINGS), chain, new X509Certificate[0]), is(Optional.empty()));
        assertThat(isNodeCertificate(new OIDClusterRequestEvaluator(SETTINGS), chain, null), is(Optional.empty()));
    }

    @Test
    public void oidEvaluatorComparesThePeerWithTheLocalCertificate() {
        final InterClusterRequestEvaluator evaluator = new OIDClusterRequestEvaluator(SETTINGS);
        final X509Certificate[] local = { certificate("CN=local", new byte[] { 1, 2, 3 }) };
        final X509Certificate[] node = { certificate("CN=peer", new byte[] { 1, 2, 3 }) };
        final X509Certificate[] other = { certificate("CN=peer", new byte[] { 9 }) };

        assertThat(isNodeCertificate(evaluator, local, node), is(Optional.of(true)));
        assertThat(isNodeCertificate(evaluator, local, other), is(Optional.of(false)));
        // Without the local certificates the OID evaluator cannot match any peer.
        assertThat(isNodeCertificate(evaluator, null, node), is(Optional.of(false)));
    }

    @Test
    public void defaultEvaluatorMatchesNodesDn() {
        final InterClusterRequestEvaluator evaluator = new DefaultInterClusterRequestEvaluator(SETTINGS);
        final X509Certificate[] local = { certificate(NODE_DN, null) };

        assertThat(isNodeCertificate(evaluator, local, new X509Certificate[] { certificate(NODE_DN, null) }), is(Optional.of(true)));
        assertThat(
            isNodeCertificate(evaluator, local, new X509Certificate[] { certificate("CN=client,OU=client,O=client,L=test,C=de", null) }),
            is(Optional.of(false))
        );
    }

    private static Optional<Boolean> isNodeCertificate(
        final InterClusterRequestEvaluator evaluator,
        final X509Certificate[] localCerts,
        final X509Certificate[] chain
    ) {
        return OpenSearchSecurityPlugin.isNodeCertificate(evaluator, new DefaultPrincipalExtractor(), localCerts, chain);
    }

    private static X509Certificate certificate(final String dn, final byte[] nodeOidExtension) {
        final X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal(dn));
        when(certificate.getExtensionValue(NODE_OID)).thenReturn(nodeOidExtension);
        return certificate;
    }
}
