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

package org.opensearch.test.framework.cluster;

import java.net.InetSocketAddress;

import org.junit.Ignore;
import org.junit.Test;

import org.opensearch.common.settings.Settings;

import reactor.netty.http.HttpProtocol;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThrows;

/**
 * FIPS variant of {@link ReactorHttpClientTests}. Two of the baseline expectations do not hold
 * under FIPS: HTTP/3 rides on a BoringSSL build that is not FIPS-validated, and plaintext
 * connections never engage the FIPS providers, so both are refused by
 * {@code ReactorHttpClient#validateProtocol}.
 */
public class ReactorHttpClientFipsIT extends ReactorHttpClientTests {

    @Override
    @Test
    public void honorsRequestedProtocol() {
        try (
            ReactorHttpClient client = new ReactorHttpClient(
                HttpProtocol.H2,
                true,
                true,
                Settings.EMPTY,
                InetSocketAddress.createUnresolved("localhost", 443)
            )
        ) {
            assertThat(client.protocol(), equalTo(HttpProtocol.H2));
        }
    }

    @Test
    public void rejectsHttp3() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new ReactorHttpClient(
                HttpProtocol.HTTP3,
                true,
                true,
                Settings.EMPTY,
                InetSocketAddress.createUnresolved("localhost", 443)
            )
        );
    }

    @Override
    @Test
    @Ignore("Plaintext connections are not permitted in FIPS mode")
    public void limitsConcurrentRequests() {}
}
