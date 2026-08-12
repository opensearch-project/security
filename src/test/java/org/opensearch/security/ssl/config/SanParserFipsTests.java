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

package org.opensearch.security.ssl.config;

import java.net.UnknownHostException;
import java.security.cert.X509Certificate;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertThrows;

/**
 * FIPS variant of {@link SanParserTest}. The BC FIPS certificate implementation surfaces a
 * malformed iPAddress SAN as an exception instead of silently dropping the whole SAN list.
 */
public class SanParserFipsTests extends SanParserTest {

    @Override
    @Test
    public void badIpSan_returnsEmpty() throws Exception {
        X509Certificate x509 = buildCertWithBadIpSan();
        RuntimeException ex = assertThrows(RuntimeException.class, () -> SanParser.parse(x509));
        assertThat(ex.getCause(), instanceOf(UnknownHostException.class));
    }
}
