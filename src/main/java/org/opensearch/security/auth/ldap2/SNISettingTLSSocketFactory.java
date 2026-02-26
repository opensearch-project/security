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

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Collections;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.IPAddress;

import org.ldaptive.ssl.ThreadLocalTLSSocketFactory;

/**
 * Custom socket factory for LDAP connections that ensures SNI hostname is properly set
 * for BouncyCastle JSSE provider hostname verification.
 *
 * <p>This addresses a known issue where JNDI LDAP's socket creation doesn't pass hostname
 * information to the SSLSocketFactory, causing BouncyCastle's hostname verification to fail.
 * @see <a href="https://github.com/bcgit/bc-java/issues/460">https://github.com/bcgit/bc-java/issues/460</a>
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

    // ThreadLocal to control whether endpoint identification should be enabled
    private static final ThreadLocal<Boolean> verifyHostnameThreadLocal = ThreadLocal.withInitial(() -> false);

    private final SSLSocketFactory delegate;

    /**
     * Required by JNDI to get the socket factory instance.
     * This method is called by JNDI when java.naming.ldap.factory.socket is set.
     */
    public static SSLSocketFactory getDefault() {
        log.debug("SNISettingTLSSocketFactory.getDefault() called by JNDI");
        // Get the configured SSL socket factory from ldaptive's ThreadLocal
        SSLSocketFactory delegate = (SSLSocketFactory) ThreadLocalTLSSocketFactory.getDefault();
        log.debug("Wrapping delegate factory: {}", delegate.getClass().getName());
        return new SNISettingTLSSocketFactory(delegate);
    }

    /**
     * A no-throw {@link AutoCloseable} returned by {@link #configure} for use in try-with-resources.
     */
    @FunctionalInterface
    public interface SniContext extends AutoCloseable {
        @Override
        void close();
    }

    /**
     * Sets SNI hostname and endpoint identification flag for the current thread, returning an
     * {@link SniContext} that clears both on close. Intended for use in try-with-resources:
     *
     * <pre>{@code
     * try (var ignored = SNISettingTLSSocketFactory.configure(hostname, verifyHostname)) {
     *     connection.open();
     * }
     * }</pre>
     */
    public static SniContext configure(String hostname, boolean verifyHostname) {
        hostnameThreadLocal.set(hostname);
        verifyHostnameThreadLocal.set(verifyHostname);
        log.debug("Configured SNI context: hostname={}, verifyHostname={}", hostname, verifyHostname);
        return SNISettingTLSSocketFactory::clearContext;
    }

    static String getHostname() {
        return hostnameThreadLocal.get();
    }

    static void clearContext() {
        hostnameThreadLocal.remove();
        verifyHostnameThreadLocal.remove();
    }

    SNISettingTLSSocketFactory(SSLSocketFactory delegate) {
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
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        log.debug("createSocket(Socket, host={}, port={}) called", host, port);
        Socket result = delegate.createSocket(socket, host, port, autoClose);
        return configureSocket(result);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        log.debug("createSocket(host={}, port={}) called", host, port);
        Socket result = delegate.createSocket(host, port);
        return configureSocket(result);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        log.debug("createSocket(host={}, port={}, localHost={}, localPort={}) called", host, port, localHost, localPort);
        Socket result = delegate.createSocket(host, port, localHost, localPort);
        return configureSocket(result);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        log.debug("createSocket(host={}, port={}) called", host, port);
        Socket result = delegate.createSocket(host, port);
        return configureSocket(result);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        log.debug("createSocket(host={}, port={}, localAddress={}, localPort={}) called", address, port, localAddress, localPort);
        Socket result = delegate.createSocket(address, port, localAddress, localPort);
        return configureSocket(result);
    }

    /**
     * Configures SNI and hostname verification on a newly created socket.
     *
     * @param socket the created socket
     * @return the configured socket
     */
    protected Socket configureSocket(Socket socket) {
        if (!(socket instanceof SSLSocket sslSocket)) {
            log.debug("Socket is not an SSLSocket, skipping SNI configuration");
            return socket;
        }

        String hostname = getHostname();

        log.debug("Configuring SNI for socket, hostname: {}", hostname);

        if (hostname == null) {
            log.warn("No hostname available for SNI configuration on socket: {}", socket.getClass().getName());
            return socket;
        }

        SSLParameters params = sslSocket.getSSLParameters();
        if (verifyHostnameThreadLocal.get()) {
            params.setEndpointIdentificationAlgorithm("LDAPS");
        }

        if (!IPAddress.isValid(hostname)) {
            log.debug("Configuring SNI for hostname: {} on socket: {}", hostname, socket.getClass().getName());
            params.setServerNames(Collections.singletonList(new SNIHostName(hostname)));
        }

        sslSocket.setSSLParameters(params);
        log.debug("Successfully configured socket for: {}", hostname);

        return socket;
    }

}
