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

import org.ldaptive.BindRequest;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.LdapException;
import org.ldaptive.Response;
import org.ldaptive.ResultCode;
import org.ldaptive.control.RequestControl;
import org.ldaptive.provider.ProviderConnection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class SniAwareConnectionTest {

    private static final String HOST = "example.com";

    @After
    public void clearThreadLocal() {
        SNISettingTLSSocketFactory.clearContext();
    }

    // --- socket-creating calls: SNI context is live during the delegate call and cleared afterwards ---

    @Test
    public void open_setsSniDuringCall_returnsDelegateResponse_clearsAfter() throws LdapException {
        RecordingConnection delegate = new RecordingConnection();
        SniAwareConnection connection = new SniAwareConnection(delegate, HOST);

        // Before open(), no context is set — the socket isn't created yet.
        assertNull(SNISettingTLSSocketFactory.getHostname());

        Response<Void> response = connection.open();

        assertEquals(HOST, delegate.hostnameAtOpen); // hostname was live during the delegate's open()
        assertSame(delegate.response, response); // delegate's response is passed straight through
        assertNull(SNISettingTLSSocketFactory.getHostname()); // and cleared afterwards (no ThreadLocal leak)
    }

    @Test
    public void openWithBindRequest_setsSniDuringCall_forwardsRequest_clearsAfter() throws LdapException {
        RecordingConnection delegate = new RecordingConnection();
        SniAwareConnection connection = new SniAwareConnection(delegate, HOST);
        BindRequest request = new BindRequest();

        Response<Void> response = connection.open(request);

        assertEquals(HOST, delegate.hostnameAtOpen);
        assertSame(request, delegate.bindRequest);
        assertSame(delegate.response, response);
        assertNull(SNISettingTLSSocketFactory.getHostname());
    }

    @Test
    public void reopen_setsSniDuringCall_returnsDelegateResponse_clearsAfter() throws LdapException {
        RecordingConnection delegate = new RecordingConnection();
        SniAwareConnection connection = new SniAwareConnection(delegate, HOST);

        Response<Void> response = connection.reopen();

        assertEquals(HOST, delegate.hostnameAtOpen);
        assertSame(delegate.response, response);
        assertNull(SNISettingTLSSocketFactory.getHostname());
    }

    @Test
    public void reopenWithBindRequest_setsSniDuringCall_forwardsRequest_clearsAfter() throws LdapException {
        RecordingConnection delegate = new RecordingConnection();
        SniAwareConnection connection = new SniAwareConnection(delegate, HOST);
        BindRequest request = new BindRequest();

        Response<Void> response = connection.reopen(request);

        assertEquals(HOST, delegate.hostnameAtOpen);
        assertSame(request, delegate.bindRequest);
        assertSame(delegate.response, response);
        assertNull(SNISettingTLSSocketFactory.getHostname());
    }

    // --- socket-creating calls clear the SNI context even when the delegate fails ---

    @Test
    public void open_clearsSniContext_whenDelegateThrows() {
        assertSniContextClearedOnFailure(SniAwareConnection::open);
    }

    @Test
    public void openWithBindRequest_clearsSniContext_whenDelegateThrows() {
        assertSniContextClearedOnFailure(connection -> connection.open(new BindRequest()));
    }

    @Test
    public void reopen_clearsSniContext_whenDelegateThrows() {
        assertSniContextClearedOnFailure(SniAwareConnection::reopen);
    }

    @Test
    public void reopenWithBindRequest_clearsSniContext_whenDelegateThrows() {
        assertSniContextClearedOnFailure(connection -> connection.reopen(new BindRequest()));
    }

    /**
     * Invokes a socket-creating call whose delegate throws, and asserts the failure propagates while
     * the SNI context was live during the call and is still cleared afterwards (try-with-resources).
     */
    private void assertSniContextClearedOnFailure(SocketCall call) {
        RecordingConnection delegate = new RecordingConnection();
        delegate.failure = new LdapException("simulated open failure");
        SniAwareConnection connection = new SniAwareConnection(delegate, HOST);

        LdapException thrown = assertThrows(LdapException.class, () -> call.invoke(connection));

        assertSame(delegate.failure, thrown); // the delegate's exception propagates unchanged
        assertEquals(HOST, delegate.hostnameAtOpen); // context was live when the delegate ran
        assertNull(SNISettingTLSSocketFactory.getHostname()); // and still cleared despite the failure
    }

    @FunctionalInterface
    private interface SocketCall {
        void invoke(SniAwareConnection connection) throws LdapException;
    }

    // --- pass-through methods: no SNI context, plain delegation ---

    @Test
    public void hostname_returnsConfiguredHostname() {
        assertEquals(HOST, new SniAwareConnection(new RecordingConnection(), HOST).hostname());
    }

    @Test
    public void getConnectionConfig_delegates() {
        RecordingConnection delegate = new RecordingConnection();
        assertSame(delegate.connectionConfig, new SniAwareConnection(delegate, HOST).getConnectionConfig());
    }

    @Test
    public void isOpen_delegates() {
        RecordingConnection delegate = new RecordingConnection();
        SniAwareConnection connection = new SniAwareConnection(delegate, HOST);

        delegate.open = true;
        assertTrue(connection.isOpen());

        delegate.open = false;
        assertFalse(connection.isOpen());
    }

    @Test
    public void getProviderConnection_delegates() {
        RecordingConnection delegate = new RecordingConnection();
        SniAwareConnection connection = new SniAwareConnection(delegate, HOST);

        assertNull(connection.getProviderConnection());
        assertTrue(delegate.getProviderConnectionCalled);
    }

    @Test
    public void close_delegates() {
        RecordingConnection delegate = new RecordingConnection();
        new SniAwareConnection(delegate, HOST).close();
        assertEquals(1, delegate.closeCalls);
    }

    @Test
    public void closeWithControls_delegates() {
        RecordingConnection delegate = new RecordingConnection();
        RequestControl[] controls = new RequestControl[0];

        new SniAwareConnection(delegate, HOST).close(controls);

        assertSame(controls, delegate.closeControls);
    }

    /**
     * Recording ldaptive {@link Connection} double: captures the SNI hostname observed during
     * open()/reopen() and records the arguments/invocations of the pass-through methods.
     */
    private static final class RecordingConnection implements Connection {
        final Response<Void> response = new Response<>(null, ResultCode.SUCCESS);
        final ConnectionConfig connectionConfig = new ConnectionConfig("ldaps://example.com:636");
        String hostnameAtOpen;
        BindRequest bindRequest;
        boolean open;
        boolean getProviderConnectionCalled;
        int closeCalls;
        RequestControl[] closeControls;
        LdapException failure;

        @Override
        public Response<Void> open() throws LdapException {
            hostnameAtOpen = SNISettingTLSSocketFactory.getHostname();
            if (failure != null) {
                throw failure;
            }
            return response;
        }

        @Override
        public Response<Void> open(BindRequest request) throws LdapException {
            bindRequest = request;
            return open();
        }

        @Override
        public Response<Void> reopen() throws LdapException {
            return open();
        }

        @Override
        public Response<Void> reopen(BindRequest request) throws LdapException {
            bindRequest = request;
            return open();
        }

        @Override
        public ConnectionConfig getConnectionConfig() {
            return connectionConfig;
        }

        @Override
        public boolean isOpen() {
            return open;
        }

        @Override
        public ProviderConnection getProviderConnection() {
            getProviderConnectionCalled = true;
            return null;
        }

        @Override
        public void close() {
            closeCalls++;
        }

        @Override
        public void close(RequestControl[] controls) {
            closeControls = controls;
        }
    }
}
