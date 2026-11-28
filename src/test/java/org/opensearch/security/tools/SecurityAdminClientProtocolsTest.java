/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.tools;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.emptyArray;

/**
 * The TLS protocols securityadmin offers, depending on the key store type given with {@code -kst}.
 */
public class SecurityAdminClientProtocolsTest {

    static final String[] TLS_1_3_AND_TLS_1_2 = { "TLSv1.3", "TLSv1.2" };

    @Test
    public void fileKeyStoreOffersTheGivenProtocols() {
        assertThat(SecurityAdmin.clientProtocols(TLS_1_3_AND_TLS_1_2, "BCFKS"), arrayContaining(TLS_1_3_AND_TLS_1_2));
        assertThat(SecurityAdmin.clientProtocols(new String[0], null), emptyArray());
    }

    @Test
    public void pkcs11KeyWithTLSv1_3AndTLSv1_2() {
        assertThat(SecurityAdmin.clientProtocols(TLS_1_3_AND_TLS_1_2, "PKCS11"), arrayContaining(TLS_1_3_AND_TLS_1_2));
    }

    @Test
    public void pkcs11KeyWithoutProtocols() {
        assertThat(SecurityAdmin.clientProtocols(new String[0], "pkcs11"), emptyArray());
    }
}
