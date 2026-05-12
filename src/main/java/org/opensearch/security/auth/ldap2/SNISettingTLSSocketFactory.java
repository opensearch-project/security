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

import java.net.Socket;
import java.util.Collections;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.ldaptive.ssl.ThreadLocalTLSSocketFactory;

/**
 * Custom socket factory for LDAP connections that ensures SNI hostname is properly set
 * for BouncyCastle JSSE provider hostname verification.
 *
 * <p>This addresses a known issue where JNDI LDAP's socket creation doesn't pass hostname
 * information to the SSLSocketFactory, causing BouncyCastle's hostname verification to fail.
 * See: https://github.com/bcgit/bc-java/issues/460
 *
 * <p>The solution wraps the delegate SSLSocketFactory and intercepts all socket creation
 * methods to set SNI parameters after socket creation but before the socket is returned to
 * the caller. The hostname is provided via ThreadLocal by the connection factory before
 * establishing the connection.
 */
public class SNISettingTLSSocketFactory extends SSLSocketFactory {

    private static final Logger log = LogManager.getLogger(SNISettingTLSSocketFactory.class);

    // ThreadLocal to store the hostname for the current LDAP connection
    private static final ThreadLocal<String> hostnameThreadLocal = new ThreadLocal<>();

    private final SSLSocketFactory delegate;

    /**
     * Required by JNDI to get the socket factory instance.
     * This method is called by JNDI when java.naming.ldap.factory.socket is set.
     */
    public static SSLSocketFactory getDefault() {
        log.debug("SNISettingTLSSocketFactory.getDefault() called by JNDI");
        // Get the configured SSL socket factory from ldaptive's ThreadLocal
        SSLSocketFactory delegate = (SSLSocketFactory) ThreadLocalTLSSocketFactory.getDefault();
        log.debug("Wrapping delegate factory: {}", delegate != null ? delegate.getClass().getName() : "NULL");
        return new SNISettingTLSSocketFactory(delegate);
    }

    /**
     * Sets the hostname for the current thread's LDAP connection.
     * This should be called before initiating the LDAP connection.
     *
     * @param hostname the LDAP server hostname
     */
    public static void setHostname(String hostname) {
        hostnameThreadLocal.set(hostname);
        log.debug("Set ThreadLocal hostname: {}", hostname);
    }

    /**
     * Clears the hostname for the current thread.
     * Should be called after the LDAP connection is established or failed.
     */
    public static void clearHostname() {
        hostnameThreadLocal.remove();
        log.debug("Cleared ThreadLocal hostname");
    }

    private SNISettingTLSSocketFactory(SSLSocketFactory delegate) {
        this.delegate = delegate;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws java.io.IOException {
        log.debug("createSocket(Socket, host={}, port={}) called", host, port);
        Socket result = delegate.createSocket(socket, host, port, autoClose);
        return configureSocket(result);
    }

    @Override
    public Socket createSocket(String host, int port) throws java.io.IOException {
        log.debug("createSocket(host={}, port={}) called", host, port);
        Socket result = delegate.createSocket(host, port);
        return configureSocket(result);
    }

    @Override
    public Socket createSocket(String host, int port, java.net.InetAddress localHost, int localPort) throws java.io.IOException {
        log.debug("createSocket(host={}, port={}, localHost, localPort) called", host, port);
        Socket result = delegate.createSocket(host, port, localHost, localPort);
        return configureSocket(result);
    }

    @Override
    public Socket createSocket(java.net.InetAddress host, int port) throws java.io.IOException {
        log.debug("createSocket(InetAddress, port={}) called", port);
        Socket result = delegate.createSocket(host, port);
        return configureSocket(result);
    }

    @Override
    public Socket createSocket(java.net.InetAddress address, int port, java.net.InetAddress localAddress, int localPort)
        throws java.io.IOException {
        log.debug("createSocket(InetAddress, port={}, localAddress, localPort={}) called", port, localPort);
        Socket result = delegate.createSocket(address, port, localAddress, localPort);
        return configureSocket(result);
    }

    /**
     * Configures SNI and hostname verification on a newly created socket.
     *
     * @param socket the created socket
     * @return the configured socket
     */
    private Socket configureSocket(Socket socket) {
        if (!(socket instanceof SSLSocket)) {
            log.debug("Socket is not an SSLSocket, skipping SNI configuration");
            return socket;
        }

        SSLSocket sslSocket = (SSLSocket) socket;
        String hostname = getHostnameForSocket(sslSocket);

        log.debug("Configuring SNI for socket, hostname from ThreadLocal: {}", hostname);

        // Clear ThreadLocal after retrieving hostname to prevent cross-test contamination
        clearHostname();

        if (hostname == null || hostname.isEmpty()) {
            log.warn("No hostname available for SNI configuration on socket: {}", socket.getClass().getName());
            return socket;
        }

        // Check if this is an IP address - skip SNI for raw IPs
        if (isIPAddress(hostname)) {
            log.debug("Hostname is an IP address ({}), skipping SNI configuration", hostname);
            return socket;
        }

        try {
            log.debug("Configuring SNI for hostname: {} on socket: {}", hostname, socket.getClass().getName());

            SSLParameters params = sslSocket.getSSLParameters();
            if (params == null) {
                log.warn("SSLParameters is null, cannot set SNI hostname");
                return socket;
            }

            // Set SNI hostname - required for BouncyCastle JSSE provider
            SNIHostName sniHostName = new SNIHostName(hostname);
            params.setServerNames(Collections.singletonList(sniHostName));

            // Enable endpoint identification for hostname verification
            params.setEndpointIdentificationAlgorithm("LDAPS");

            sslSocket.setSSLParameters(params);

            log.debug("Successfully configured SNI hostname: {} and endpoint identification", hostname);
        } catch (Exception e) {
            log.error("Failed to configure SNI hostname '{}' on SSL socket: {}", hostname, e.getMessage(), e);
        }

        return socket;
    }

    /**
     * Attempts to determine the hostname for the socket.
     * First checks ThreadLocal, then tries to extract from socket's peer.
     *
     * @param socket the SSL socket
     * @return the hostname, or null if not available
     */
    private String getHostnameForSocket(SSLSocket socket) {
        // First try ThreadLocal
        String hostname = hostnameThreadLocal.get();
        if (hostname != null && !hostname.isEmpty()) {
            return hostname;
        }

        // Try to get from socket's remote address
        if (socket.getInetAddress() != null) {
            hostname = socket.getInetAddress().getHostName();
            if (hostname != null && !hostname.equals(socket.getInetAddress().getHostAddress())) {
                return hostname;
            }
        }

        return null;
    }

    /**
     * Checks if the given string is an IP address.
     *
     * @param host the hostname to check
     * @return true if it's an IP address
     */
    private boolean isIPAddress(String host) {
        if (host == null || host.indexOf('.') <= 0) {
            return false;
        }
        return org.bouncycastle.util.IPAddress.isValid(host);
    }
}
