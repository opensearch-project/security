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
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.IPAddress;

import org.ldaptive.ssl.SslConfig;
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
 * the caller. The hostname is provided via ThreadLocal by {@link SniJndiProvider} for each
 * LDAP URL a connection tries.
 */
public class SNISettingTLSSocketFactory extends SSLSocketFactory {

    private static final Logger log = LogManager.getLogger(SNISettingTLSSocketFactory.class);

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
        log.debug("Wrapping delegate factory: {}", delegate.getClass().getName());
        return new SNISettingTLSSocketFactory(delegate);
    }

    /**
     * A no-throw {@link AutoCloseable} returned by {@link #configure} for use in try-with-resources.
     */
    @FunctionalInterface
    interface SniContext extends AutoCloseable {
        @Override
        void close();
    }

    /**
     * Sets the SNI hostname, and ldaptive's thread-local TLS configuration that {@link #getDefault()}
     * wraps, for the current thread. The returned {@link SniContext} clears the hostname and restores
     * the previous TLS configuration on close. Only {@link SniJndiProvider} calls this, around the
     * JNDI connect to each LDAP URL:
     *
     * <pre>{@code
     * try (var ignored = SNISettingTLSSocketFactory.configure(hostname, sslConfig)) {
     *     return super.createInternal(url);
     * }
     * }</pre>
     *
     * <p>ldaptive sets the TLS thread-local only on the thread that calls {@code getConnection()}, and
     * it re-applies it on later opens only when JNDI uses {@link ThreadLocalTLSSocketFactory} itself.
     * With this factory registered instead, a {@code reopen()} on another thread (ldaptive's default
     * reopen handler, run by whichever thread hits a dropped connection) would otherwise find no
     * configuration, or the one of another LDAP domain last used on that thread.
     *
     * @param sslConfig the configuration captured when the connection was created, or {@code null}
     *                  to leave the thread-local untouched
     */
    static SniContext configure(String hostname, SslConfig sslConfig) {
        hostnameThreadLocal.set(hostname);
        log.debug("Configured SNI context: hostname={}", hostname);
        if (sslConfig == null) {
            return SNISettingTLSSocketFactory::clearContext;
        }
        ThreadLocalTLSSocketFactory threadLocalConfig = new ThreadLocalTLSSocketFactory();
        SslConfig previous = threadLocalConfig.getSslConfig();
        threadLocalConfig.setSslConfig(sslConfig);
        return () -> {
            clearContext();
            threadLocalConfig.setSslConfig(previous);
        };
    }

    /** ldaptive's thread-local TLS configuration for the current thread, or {@code null} if none is set. */
    static SslConfig currentSslConfig() {
        return new ThreadLocalTLSSocketFactory().getSslConfig();
    }

    static String getHostname() {
        return hostnameThreadLocal.get();
    }

    static void clearContext() {
        hostnameThreadLocal.remove();
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

    /**
     * Unconnected socket, which JNDI requests when {@code connect_timeout} is set and then connects
     * itself with that timeout. Without this override, the inherited method throws and JNDI falls
     * back to {@link #createSocket(String, int)}, which connects without any timeout.
     */
    @Override
    public Socket createSocket() throws IOException {
        log.debug("createSocket() called");
        Socket result = delegate.createSocket();
        return configureSocket(result);
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
     * Sets the SNI {@code server_name} on a newly created socket from the hostname carried on the
     * ThreadLocal. Hostname <em>verification</em> is handled by JNDI's endpoint identification (and
     * ldaptive's verifier) — not here.
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
        String sniName = toSniName(hostname);
        if (sniName != null) {
            log.debug("Configuring SNI for hostname: {} on socket: {}", sniName, socket.getClass().getName());
            params.setServerNames(List.of(new SNIHostName(sniName)));
        }

        sslSocket.setSSLParameters(params);
        log.debug("Successfully configured socket for: {}", hostname);

        return socket;
    }

    /**
     * Normalizes a configured LDAP host into an SNI {@code HostName}, following RFC 6066 section 3
     * and the JDK's own handling: literal IPv4/IPv6 addresses (including bracketed IPv6 as returned
     * by {@link java.net.URI#getHost()}) are not permitted and yield {@code null} (no SNI), and a
     * trailing dot of a fully qualified name is dropped.
     *
     * <p>Unlike SunJSSE, single-label names (e.g. {@code localhost}) are kept and invalid names fail
     * loudly in {@link SNIHostName}, because under BCJSSE the SNI value is also the hostname used for
     * endpoint identification. The same rules apply under SunJSSE, so behaviour does not depend on the
     * provider.
     */
    static String toSniName(String hostname) {
        String name = hostname;
        if (name.startsWith("[") && name.endsWith("]")) {
            name = name.substring(1, name.length() - 1);
        }
        if (IPAddress.isValid(name)) {
            return null;
        }
        if (name.endsWith(".")) {
            name = name.substring(0, name.length() - 1);
        }
        return name;
    }

}
