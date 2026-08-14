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

package org.opensearch.security.http;

/**
 * FIPS variant of {@link UntrustedLdapServerCertificateTest}. BCJSSE aborts the handshake with
 * its own alert type instead of the JSSE {@code SSLHandshakeException}.
 */
public class UntrustedLdapServerCertificateFipsIT extends UntrustedLdapServerCertificateTest {

    @Override
    protected String getUntrustedCertificateExceptionName() {
        return "org.bouncycastle.tls.TlsFatalAlert";
    }
}
