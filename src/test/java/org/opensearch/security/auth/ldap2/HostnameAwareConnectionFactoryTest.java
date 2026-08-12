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

import org.ldaptive.Connection;
import org.ldaptive.ConnectionConfig;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class HostnameAwareConnectionFactoryTest {

    @After
    public void clearThreadLocal() {
        SNISettingTLSSocketFactory.clearContext();
    }

    @Test
    public void getConnection_wrapsWithHostnameFromUrl_withoutSettingContextAtBuild() {
        HostnameAwareConnectionFactory factory = new HostnameAwareConnectionFactory(
            new ConnectionConfig("ldaps://example.com:636"),
            "ldaps://example.com:636"
        );

        Connection connection = factory.getConnection();

        // The connection is wrapped with the hostname parsed from the LDAP URL; the wrapper then
        // establishes it as the SNI context at open() — see SniAwareConnectionTest.
        assertTrue(connection instanceof SniAwareConnection);
        assertEquals("example.com", ((SniAwareConnection) connection).hostname());
        // Building the connection must NOT set the context — the socket isn't created yet.
        assertNull(SNISettingTLSSocketFactory.getHostname());
    }

    @Test(expected = IllegalArgumentException.class)
    public void getConnection_throwsOnUnparseableUrl() {
        new HostnameAwareConnectionFactory(new ConnectionConfig("ldaps://example.com:636"), "not-a-valid-url").getConnection();
    }
}
