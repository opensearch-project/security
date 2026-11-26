/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.ssl.config;

import java.util.List;

import org.junit.Test;

import org.opensearch.OpenSearchException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;

/**
 * In FIPS mode SunJSSE cannot derive TLS 1.2 keys, so a PKCS#11 key negotiates TLS 1.3 only.
 */
public class Pkcs11NegotiableProtocolsFipsTests extends Pkcs11NegotiableProtocolsTest {

    @Override
    @Test
    public void negotiableProtocolsOfTLSv1_3AndTLSv1_2() {
        assertThat(configuration.negotiableProtocols(TLS_1_3_AND_TLS_1_2), is(List.of("TLSv1.3")));
    }

    @Test
    public void rejectsEnabledProtocolsWithoutTLSv1_3() {
        assertThrows(OpenSearchException.class, () -> configuration.negotiableProtocols(List.of("TLSv1.2")));
    }
}
