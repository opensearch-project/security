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
import org.opensearch.security.ssl.config.KeyStoreConfiguration.Pkcs11KeyStoreConfiguration;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;

/**
 * The protocols a TLS context with a PKCS#11 key can negotiate. The key is never loaded, so no token is needed.
 */
public class Pkcs11NegotiableProtocolsTest {

    static final List<String> TLS_1_3_AND_TLS_1_2 = List.of("TLSv1.3", "TLSv1.2");

    final KeyStoreConfiguration configuration = new Pkcs11KeyStoreConfiguration(
        null,
        StorePassword.of("token-pin".toCharArray()),
        StorePassword.of("token-pin".toCharArray())
    );

    @Test
    public void negotiableProtocolsOfTLSv1_3AndTLSv1_2() {
        assertThat(configuration.negotiableProtocols(TLS_1_3_AND_TLS_1_2), is(TLS_1_3_AND_TLS_1_2));
    }

    @Test
    public void protocolsInFipsModeKeepOnlyTLSv1_3() {
        assertThat(Pkcs11KeyStoreConfiguration.protocolsInFipsMode(TLS_1_3_AND_TLS_1_2), is(List.of("TLSv1.3")));
    }

    @Test
    public void protocolsInFipsModeRejectProtocolsWithoutTLSv1_3() {
        final OpenSearchException e = assertThrows(
            OpenSearchException.class,
            () -> Pkcs11KeyStoreConfiguration.protocolsInFipsMode(List.of("TLSv1.2"))
        );
        assertThat(
            e.getMessage(),
            is(
                "A PKCS#11 key store supports only TLSv1.3 in FIPS mode, but the enabled protocols are [TLSv1.2]."
                    + " Add TLSv1.3 to the enabled protocols."
            )
        );
    }
}
