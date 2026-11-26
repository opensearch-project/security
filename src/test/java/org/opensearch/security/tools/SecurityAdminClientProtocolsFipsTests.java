/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.tools;

import org.junit.Test;

import org.opensearch.OpenSearchException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContaining;
import static org.junit.Assert.assertThrows;

/**
 * In FIPS mode securityadmin offers TLS 1.3 by default with a PKCS#11 key, and protocols given with -ep must include it.
 * The given protocols are used as they are.
 */
public class SecurityAdminClientProtocolsFipsTests extends SecurityAdminClientProtocolsTest {

    @Override
    @Test
    public void pkcs11KeyWithoutProtocols() {
        assertThat(SecurityAdmin.clientProtocols(new String[0], "pkcs11"), arrayContaining("TLSv1.3"));
    }

    @Test
    public void pkcs11KeyRejectsProtocolsWithoutTLSv1_3() {
        assertThrows(OpenSearchException.class, () -> SecurityAdmin.clientProtocols(new String[] { "TLSv1.2" }, "PKCS11"));
    }
}
