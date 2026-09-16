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
 * HTTP/3 rides on a BoringSSL build that is not from the FIPS-validated branch, so
 * {@code ReactorHttpClient} refuses it in FIPS mode.
 */
public class ResourceFocusedFipsIT extends ResourceFocusedTests {

    @Override
    protected HttpProtocol genericClientProtocol() {
        return HttpProtocol.H2;
    }
}
