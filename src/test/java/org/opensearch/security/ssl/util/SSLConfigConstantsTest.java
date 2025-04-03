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
package org.opensearch.security.ssl.util;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.ssl.config.CertType;

import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_ENABLED_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS;
import static org.junit.Assert.assertArrayEquals;

public class SSLConfigConstantsTest {
    private static final String[] TLSV1_123 = new String[] { "TLSv1.3", "TLSv1.2", "TLSv1.1" };
    private static final String[] TLSV1_01 = new String[] { "TLSv1", "TLSv1.1" };

    @Test
    public void testDefaultTLSProtocols() {
        assertArrayEquals(TLSV1_123, SSLConfigConstants.getSecureSSLProtocols(Settings.EMPTY, CertType.HTTP));
        assertArrayEquals(TLSV1_123, SSLConfigConstants.getSecureSSLProtocols(Settings.EMPTY, CertType.AUX));
        assertArrayEquals(TLSV1_123, SSLConfigConstants.getSecureSSLProtocols(Settings.EMPTY, CertType.TRANSPORT));
    }

    @Test
    public void testCustomTLSProtocols() {
        assertArrayEquals(
            TLSV1_01,
            SSLConfigConstants.getSecureSSLProtocols(
                Settings.builder().putList(SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, TLSV1_01).build(),
                CertType.HTTP
            )
        );
        assertArrayEquals(
            TLSV1_01,
            SSLConfigConstants.getSecureSSLProtocols(
                Settings.builder().putList(SECURITY_SSL_AUX_ENABLED_PROTOCOLS, TLSV1_01).build(),
                CertType.AUX
            )
        );
        assertArrayEquals(
            TLSV1_01,
            SSLConfigConstants.getSecureSSLProtocols(
                Settings.builder().putList(SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, TLSV1_01).build(),
                CertType.TRANSPORT
            )
        );
    }

    @Test
    public void testCustomSSLProtocols() {
        final var sslDefaultProtocols = SSLConfigConstants.getSecureSSLProtocols(
            Settings.builder().putList(SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, TLSV1_01).build(),
            CertType.HTTP
        );
        assertArrayEquals(TLSV1_01, sslDefaultProtocols);
    }
}
