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

import org.ldaptive.BindRequest;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.LdapException;
import org.ldaptive.Response;
import org.ldaptive.control.RequestControl;
import org.ldaptive.provider.ProviderConnection;

/**
 * {@link Connection} decorator that establishes the {@link SNISettingTLSSocketFactory} SNI
 * context for the duration of every socket-creating call ({@code open} / {@code reopen}).
 *
 * <p>ldaptive's {@code getConnection()} returns an <em>unopened</em> connection; the TLS socket
 * is created later, at {@code open()}. Setting the SNI ThreadLocal only around
 * {@code getConnection()} therefore clears it before the socket exists, so the socket factory
 * sees no hostname (no SNI) and no verify flag (hostname verification skipped). Wrapping
 * {@code open()}/{@code reopen()} keeps the hostname and verify flag available exactly when the
 * socket is created — for non-pooled and pooled connections alike, since a pool opens
 * connections on the thread that initialises/borrows them.
 *
 * <p>This whole mechanism (this decorator + the SNI ThreadLocal in
 * {@link SNISettingTLSSocketFactory} + {@link HostnameAwareConnectionFactory}) is a workaround for
 * the JNDI LDAP provider resolving hostnames to IPs before socket creation (bc-java#460). ldaptive
 * 2.x's native (Netty) transport opens sockets with the real hostname, giving SNI and hostname
 * verification natively — migrating off the JNDI provider would remove this class,
 * {@link SNISettingTLSSocketFactory}, and {@link HostnameAwareConnectionFactory}.
 */
class SniAwareConnection implements Connection {

    private final Connection delegate;
    private final String hostname;

    SniAwareConnection(Connection delegate, String hostname) {
        this.delegate = delegate;
        this.hostname = hostname;
    }

    /** The SNI hostname this connection establishes at {@code open()}. Package-private for tests. */
    String hostname() {
        return hostname;
    }

    @Override
    public Response<Void> open() throws LdapException {
        try (var ignored = SNISettingTLSSocketFactory.configure(hostname)) {
            return delegate.open();
        }
    }

    @Override
    public Response<Void> open(BindRequest request) throws LdapException {
        try (var ignored = SNISettingTLSSocketFactory.configure(hostname)) {
            return delegate.open(request);
        }
    }

    @Override
    public Response<Void> reopen() throws LdapException {
        try (var ignored = SNISettingTLSSocketFactory.configure(hostname)) {
            return delegate.reopen();
        }
    }

    @Override
    public Response<Void> reopen(BindRequest request) throws LdapException {
        try (var ignored = SNISettingTLSSocketFactory.configure(hostname)) {
            return delegate.reopen(request);
        }
    }

    @Override
    public ConnectionConfig getConnectionConfig() {
        return delegate.getConnectionConfig();
    }

    @Override
    public boolean isOpen() {
        return delegate.isOpen();
    }

    @Override
    public ProviderConnection getProviderConnection() {
        return delegate.getProviderConnection();
    }

    @Override
    public void close() {
        delegate.close();
    }

    @Override
    public void close(RequestControl[] controls) {
        delegate.close(controls);
    }
}
