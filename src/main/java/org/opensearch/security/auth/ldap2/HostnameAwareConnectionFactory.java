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
import org.ldaptive.ConnectionConfig;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.LdapURL;

/**
 * {@link DefaultConnectionFactory} that extracts the hostname from the LDAP URL and returns a
 * {@link SniAwareConnection}, so the SNI context is established when the connection is opened —
 * the TLS socket is created at {@code open()}, not at {@code getConnection()}.
 *
 * <p>Extending {@link DefaultConnectionFactory} (rateher than merely implementing
 * {@code ConnectionFactory}) lets the same class back a connection pool, which requires a
 * concrete {@link DefaultConnectionFactory}, as well as serve non-pooled connections directly.
 * The pool creates each physical connection via {@link #getConnection()} and then calls
 * {@code open()} on it, so the SNI wrapping applies uniformly to pooled and non-pooled paths.
 *
 * <p>This is necessary because JNDI LDAP resolves hostnames to IP addresses before creating
 * SSL sockets, making the hostname unavailable for SNI configuration.
 */
public class HostnameAwareConnectionFactory extends DefaultConnectionFactory {

    private final String ldapUrl;

    public HostnameAwareConnectionFactory(ConnectionConfig config, String ldapUrl) {
        super(config);
        this.ldapUrl = ldapUrl;
    }

    @Override
    public Connection getConnection() {
        String hostname = new LdapURL(ldapUrl).getEntry().getHostname();
        return new SniAwareConnection(super.getConnection(), hostname);
    }
}
