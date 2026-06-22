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

import java.net.InetAddress;
import java.net.Socket;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.After;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

public class SNISettingTLSSocketFactoryTest {

    private final SNISettingTLSSocketFactory factory = new SNISettingTLSSocketFactory(null);

    @After
    public void clearThreadLocal() {
        SNISettingTLSSocketFactory.clearContext();
    }

    // --- configureSocket ---

    @Test
    public void configureSocket_setsSniAndEndpointIdentification_whenVerifyHostname() throws Exception {
        SSLSocket socket = (SSLSocket) SSLContext.getDefault().getSocketFactory().createSocket();
        SNISettingTLSSocketFactory.configure("example.com", true);

        factory.configureSocket(socket);

        List<SNIServerName> serverNames = socket.getSSLParameters().getServerNames();
        assertEquals(1, serverNames.size());
        assertEquals("example.com", ((SNIHostName) serverNames.get(0)).getAsciiName());
        assertEquals("LDAPS", socket.getSSLParameters().getEndpointIdentificationAlgorithm());
    }

    @Test
    public void configureSocket_setsSniButNotEndpointIdentification_whenVerifyHostnameDisabled() throws Exception {
        SSLSocket socket = (SSLSocket) SSLContext.getDefault().getSocketFactory().createSocket();
        SNISettingTLSSocketFactory.configure("example.com", false);

        factory.configureSocket(socket);

        List<SNIServerName> serverNames = socket.getSSLParameters().getServerNames();
        assertEquals(1, serverNames.size());
        assertEquals("example.com", ((SNIHostName) serverNames.get(0)).getAsciiName());
        assertNull(socket.getSSLParameters().getEndpointIdentificationAlgorithm());
    }

    @Test
    public void configureSocket_skipsSnForIpAddress() throws Exception {
        SSLSocket socket = (SSLSocket) SSLContext.getDefault().getSocketFactory().createSocket();
        SNISettingTLSSocketFactory.configure("192.168.1.1", true);

        factory.configureSocket(socket);

        assertNull(socket.getSSLParameters().getServerNames());
        assertEquals("LDAPS", socket.getSSLParameters().getEndpointIdentificationAlgorithm());
    }

    @Test
    public void configureSocket_skipsWhenNoHostname() throws Exception {
        SSLSocket socket = (SSLSocket) SSLContext.getDefault().getSocketFactory().createSocket();

        factory.configureSocket(socket);

        assertNull(socket.getSSLParameters().getServerNames());
        assertNull(socket.getSSLParameters().getEndpointIdentificationAlgorithm());
    }

    @Test(expected = IllegalArgumentException.class)
    public void configureSocket_throwsOnInvalidHostname() throws Exception {
        SSLSocket socket = (SSLSocket) SSLContext.getDefault().getSocketFactory().createSocket();
        SNISettingTLSSocketFactory.configure("invalid..hostname", true);

        factory.configureSocket(socket);
    }

    @Test
    public void configureSocket_passesThroughNonSslSocket() {
        Socket socket = new Socket();
        SNISettingTLSSocketFactory.configure("example.com", true);

        Socket result = factory.configureSocket(socket);

        assertSame(socket, result);
    }

    // --- cipher suite delegation ---

    @Test
    public void getDefaultCipherSuites_delegatesToDelegate() throws Exception {
        SSLSocketFactory real = SSLContext.getDefault().getSocketFactory();
        SNISettingTLSSocketFactory f = new SNISettingTLSSocketFactory(real);

        assertEquals(real.getDefaultCipherSuites(), f.getDefaultCipherSuites());
    }

    @Test
    public void getSupportedCipherSuites_delegatesToDelegate() throws Exception {
        SSLSocketFactory real = SSLContext.getDefault().getSocketFactory();
        SNISettingTLSSocketFactory f = new SNISettingTLSSocketFactory(real);

        assertEquals(real.getSupportedCipherSuites(), f.getSupportedCipherSuites());
    }

    // --- createSocket ---

    @Test
    public void createSocket_wrappingSocket_configuresSni() throws Exception {
        SSLSocket sslSocket = (SSLSocket) SSLContext.getDefault().getSocketFactory().createSocket();
        SNISettingTLSSocketFactory f = new SNISettingTLSSocketFactory(stubDelegate(sslSocket));
        SNISettingTLSSocketFactory.configure("example.com", false);

        Socket result = f.createSocket(new Socket(), "example.com", 636, true);

        assertSame(sslSocket, result);
        assertEquals("example.com", ((SNIHostName) ((SSLSocket) result).getSSLParameters().getServerNames().get(0)).getAsciiName());
    }

    @Test
    public void createSocket_stringHost_configuresSni() throws Exception {
        SSLSocket sslSocket = (SSLSocket) SSLContext.getDefault().getSocketFactory().createSocket();
        SNISettingTLSSocketFactory f = new SNISettingTLSSocketFactory(stubDelegate(sslSocket));
        SNISettingTLSSocketFactory.configure("example.com", false);

        Socket result = f.createSocket("example.com", 636);

        assertSame(sslSocket, result);
        assertEquals("example.com", ((SNIHostName) ((SSLSocket) result).getSSLParameters().getServerNames().get(0)).getAsciiName());
    }

    @Test
    public void createSocket_stringHostWithLocalAddress_configuresSni() throws Exception {
        SSLSocket sslSocket = (SSLSocket) SSLContext.getDefault().getSocketFactory().createSocket();
        SNISettingTLSSocketFactory f = new SNISettingTLSSocketFactory(stubDelegate(sslSocket));
        SNISettingTLSSocketFactory.configure("example.com", false);

        Socket result = f.createSocket("example.com", 636, InetAddress.getLoopbackAddress(), 0);

        assertSame(sslSocket, result);
        assertEquals("example.com", ((SNIHostName) ((SSLSocket) result).getSSLParameters().getServerNames().get(0)).getAsciiName());
    }

    @Test
    public void createSocket_inetAddress_configuresSni() throws Exception {
        SSLSocket sslSocket = (SSLSocket) SSLContext.getDefault().getSocketFactory().createSocket();
        SNISettingTLSSocketFactory f = new SNISettingTLSSocketFactory(stubDelegate(sslSocket));
        SNISettingTLSSocketFactory.configure("example.com", false);

        Socket result = f.createSocket(InetAddress.getLoopbackAddress(), 636);

        assertSame(sslSocket, result);
        assertEquals("example.com", ((SNIHostName) ((SSLSocket) result).getSSLParameters().getServerNames().get(0)).getAsciiName());
    }

    @Test
    public void createSocket_inetAddressWithLocalAddress_configuresSni() throws Exception {
        SSLSocket sslSocket = (SSLSocket) SSLContext.getDefault().getSocketFactory().createSocket();
        SNISettingTLSSocketFactory f = new SNISettingTLSSocketFactory(stubDelegate(sslSocket));
        SNISettingTLSSocketFactory.configure("example.com", false);

        Socket result = f.createSocket(InetAddress.getLoopbackAddress(), 636, InetAddress.getLoopbackAddress(), 0);

        assertSame(sslSocket, result);
        assertEquals("example.com", ((SNIHostName) ((SSLSocket) result).getSSLParameters().getServerNames().get(0)).getAsciiName());
    }

    private static SSLSocketFactory stubDelegate(Socket socket) {
        return new SSLSocketFactory() {
            public String[] getDefaultCipherSuites() {
                return new String[0];
            }

            public String[] getSupportedCipherSuites() {
                return new String[0];
            }

            public Socket createSocket(Socket s, String host, int port, boolean autoClose) {
                return socket;
            }

            public Socket createSocket(String host, int port) {
                return socket;
            }

            public Socket createSocket(String host, int port, InetAddress localHost, int localPort) {
                return socket;
            }

            public Socket createSocket(InetAddress host, int port) {
                return socket;
            }

            public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) {
                return socket;
            }
        };
    }
}
