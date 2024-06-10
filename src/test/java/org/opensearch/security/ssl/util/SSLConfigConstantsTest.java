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

import java.util.List;

import org.junit.Test;

import org.opensearch.common.settings.Settings;

import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS;
import static org.junit.Assert.assertArrayEquals;

public class SSLConfigConstantsTest {

    @Test
    public void testDefaultTLSProtocols() {
        final var tlsDefaultProtocols = SSLConfigConstants.getSecureSSLProtocols(Settings.EMPTY, false);
        assertArrayEquals(new String[] { "TLSv1.3", "TLSv1.2", "TLSv1.1" }, tlsDefaultProtocols);
    }

    @Test
    public void testDefaultSSLProtocols() {
        final var sslDefaultProtocols = SSLConfigConstants.getSecureSSLProtocols(Settings.EMPTY, true);
        assertArrayEquals(new String[] { "TLSv1.3", "TLSv1.2", "TLSv1.1" }, sslDefaultProtocols);
    }

    @Test
    public void testCustomTLSProtocols() {
        final var tlsDefaultProtocols = SSLConfigConstants.getSecureSSLProtocols(
            Settings.builder().putList(SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, List.of("TLSv1", "TLSv1.1")).build(),
            false
        );
        assertArrayEquals(new String[] { "TLSv1", "TLSv1.1" }, tlsDefaultProtocols);
    }

    @Test
    public void testCustomSSLProtocols() {
        final var sslDefaultProtocols = SSLConfigConstants.getSecureSSLProtocols(
            Settings.builder().putList(SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, List.of("TLSv1", "TLSv1.1")).build(),
            true
        );
        assertArrayEquals(new String[] { "TLSv1", "TLSv1.1" }, sslDefaultProtocols);
    }

}
