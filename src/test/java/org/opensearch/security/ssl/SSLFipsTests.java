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

package org.opensearch.security.ssl;

/**
 * FIPS variant of {@link SSLTest}. Requesting SSLv3 stays in scope under FIPS: it is a
 * reachable client misconfiguration, so the suite asserts how it breaks rather than skipping.
 * BCJSSE refuses to accept the protocol list at all, so the request never reaches a handshake.
 */
public class SSLFipsTests extends SSLTest {

    @Override
    protected void expectSslV3Rejection() {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("'protocols' cannot be null, or contain unsupported protocols");
    }
}
