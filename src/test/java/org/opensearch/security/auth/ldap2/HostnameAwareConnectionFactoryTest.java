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

import org.junit.After;
import org.junit.Test;

import org.ldaptive.LdapException;

import static org.junit.Assert.assertEquals;

public class HostnameAwareConnectionFactoryTest {

    @After
    public void clearThreadLocal() {
        SNISettingTLSSocketFactory.clearContext();
    }

    @Test
    public void getConnection_setsHostnameBeforeDelegating() throws LdapException {
        String[] captured = { null };
        new HostnameAwareConnectionFactory(() -> {
            captured[0] = SNISettingTLSSocketFactory.getHostname();
            return null;
        }, "ldaps://example.com:636", true).getConnection();

        assertEquals("example.com", captured[0]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getConnection_throwsOnUnparseableUrl() throws LdapException {
        new HostnameAwareConnectionFactory(() -> null, "not-a-valid-url", false).getConnection();
    }
}
