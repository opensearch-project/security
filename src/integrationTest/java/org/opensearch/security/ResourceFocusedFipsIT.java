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

import reactor.netty.http.HttpProtocol;

/**
 * FIPS variant of {@link ResourceFocusedTests}. The generic-client scenarios run over HTTP/2:
 * QUIC uses the bundled BoringSSL instead of the FIPS provider, so the nodes do not offer HTTP/3
 * in FIPS mode and {@code ReactorHttpClient} refuses it.
 */
public class ResourceFocusedFipsIT extends ResourceFocusedTests {

    @Override
    protected HttpProtocol genericClientProtocol() {
        return HttpProtocol.H2;
    }
}
