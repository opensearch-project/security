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

package org.opensearch.security.auth.ldap;

import org.junit.Ignore;
import org.junit.Test;

/**
 * FIPS variant of {@link LdapBackendTest}. Everything except the SSLv3 case behaves identically under the BC FIPS
 * providers, so only that one is overridden.
 */
public class LdapBackendFipsTests extends LdapBackendTest {

    @Override
    @Test
    @Ignore("Deadlocks the embedded LDAP server under FIPS: teardown close() contends with an untimed BCJSSE handshake read")
    public void testLdapAuthenticationSSLSSLv3() {}
}
