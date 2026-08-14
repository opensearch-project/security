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

package org.opensearch.security.auth.ldap2;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * FIPS variant of {@link LdapBackendTestNewStyleConfig2}. BCJSSE rejects an unusable cipher-suite list with different wording from
 * the JDK provider, so only that expectation is overridden.
 */
@RunWith(Parameterized.class)
public class LdapBackendTestNewStyleConfig2FipsTests extends LdapBackendTestNewStyleConfig2 {

    @Override
    protected String getUnsupportedCipherMessage() {
        return "No usable cipher suites enabled";
    }

    @Override
    @Test
    @Ignore("Deadlocks the embedded LDAP server under FIPS: teardown close() contends with an untimed BCJSSE handshake read")
    public void testLdapAuthenticationSSLSSLv3() {}
}
