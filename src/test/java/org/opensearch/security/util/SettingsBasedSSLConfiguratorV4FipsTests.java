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

package org.opensearch.security.util;

import org.bouncycastle.tls.TlsFatalAlert;

/**
 * FIPS variant of {@link SettingsBasedSSLConfiguratorV4Test}. BCJSSE aborts an untrusted
 * handshake with its own alert type rather than the JSSE {@code SSLHandshakeException}.
 */
public class SettingsBasedSSLConfiguratorV4FipsTests extends SettingsBasedSSLConfiguratorV4Test {

    @Override
    protected Class<? extends Throwable> getWrongTrustExceptionClass() {
        return TlsFatalAlert.class;
    }
}
