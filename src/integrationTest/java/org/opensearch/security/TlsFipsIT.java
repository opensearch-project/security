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

import javax.net.ssl.SSLHandshakeException;

/**
 * FIPS variant of {@link TlsTests}. BCJSSE rejects an unusable cipher-suite list while the
 * client is being set up, so the failure surfaces as an {@link IllegalStateException} rather
 * than an {@link SSLHandshakeException} raised mid-handshake.
 */
public class TlsFipsIT extends TlsTests {

    @Override
    protected Class<? extends Throwable> getUnsupportedCipherSuiteException() {
        return IllegalStateException.class;
    }
}
