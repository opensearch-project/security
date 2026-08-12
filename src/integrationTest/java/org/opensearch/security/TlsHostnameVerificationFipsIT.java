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

/**
 * FIPS variant of {@link TlsHostnameVerificationTests}. BCJSSE reports the hostname mismatch
 * from inside the handshake stack trace and words the message in the singular.
 */
public class TlsHostnameVerificationFipsIT extends TlsHostnameVerificationTests {

    @Override
    protected void assertHostnameVerificationFailureLogged() {
        logsRule.assertThatStackTraceContain("No subject alternative name found matching IP address 127.0.0.1");
    }
}
