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

import org.ldaptive.Connection;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.LdapException;
import org.ldaptive.LdapURL;

/**
 * Wrapper around ConnectionFactory that extracts the hostname from the LDAP URL
 * and stores it in ThreadLocal for use by SNISettingTLSSocketFactory.
 *
 * <p>This is necessary because JNDI LDAP resolves hostnames to IP addresses before
 * creating SSL sockets, making the hostname unavailable for SNI configuration.
 */
public record HostnameAwareConnectionFactory(ConnectionFactory delegate, String ldapUrl, boolean verifyHostname)
    implements
        ConnectionFactory {

    @Override
    public Connection getConnection() throws LdapException {
        String hostname = new LdapURL(ldapUrl).getEntry().getHostname();
        try (var ignored = SNISettingTLSSocketFactory.configure(hostname, verifyHostname)) {
            return delegate.getConnection();
        }
    }
}
