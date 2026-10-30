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

import java.util.Locale;
import java.util.Map;
import javax.net.ssl.SSLSocketFactory;

import org.ldaptive.ConnectionConfig;
import org.ldaptive.ConnectionStrategy;
import org.ldaptive.LdapException;
import org.ldaptive.LdapURL;
import org.ldaptive.provider.jndi.JndiConnection;
import org.ldaptive.provider.jndi.JndiConnectionFactory;
import org.ldaptive.provider.jndi.JndiProvider;
import org.ldaptive.provider.jndi.JndiProviderConfig;
import org.ldaptive.ssl.SslConfig;
import org.ldaptive.ssl.ThreadLocalTLSSocketFactory;

/**
 * {@link JndiProvider} that establishes the {@link SNISettingTLSSocketFactory} context for every LDAP URL a connection
 * tries, so the SNI name is the host actually being connected to. It takes effect where the provider configuration
 * registers {@link SNISettingTLSSocketFactory} as JNDI socket factory ({@code java.naming.ldap.factory.socket}).
 *
 * <p>ldaptive fails over between the configured hosts itself: each {@code open()}/{@code reopen()} calls
 * {@link JndiConnectionFactory#createInternal(String)} once per URL, in the order of the connection strategy, until one
 * succeeds. Under BCJSSE the SNI name is also the name the server certificate is verified against, so it has to follow
 * that loop. Pooled connections, user binds and reopens all go through it as well.
 *
 * <p>ldaptive's thread-local TLS configuration, which {@link SNISettingTLSSocketFactory#getDefault()} wraps, is set on
 * the thread that calls {@code getConnection()}. ldaptive re-applies it on later opens only when JNDI uses
 * {@link ThreadLocalTLSSocketFactory} itself; this provider does the same for {@link SNISettingTLSSocketFactory}, so a
 * reopen on another thread (ldaptive's default reopen handler) uses the configuration of its own connection.
 *
 * <p>This works around the JNDI LDAP provider not passing the hostname to the socket factory (bc-java#460). ldaptive
 * 2.x's own transport connects with the hostname, which would make this class and {@link SNISettingTLSSocketFactory}
 * unnecessary, see https://github.com/opensearch-project/security/issues/2959.
 */
public class SniJndiProvider extends JndiProvider {

    /** Same as ldaptive 1.2.3's {@code JndiProvider#getJndiConnectionFactory}, but creates a {@link SniJndiConnectionFactory}. */
    @Override
    protected JndiConnectionFactory getJndiConnectionFactory(ConnectionConfig cc, Map<String, Object> env) {
        JndiProviderConfig config = getProviderConfig();
        SSLSocketFactory factory = config.getSslSocketFactory();
        if (factory == null && (cc.getUseSSL() || cc.getLdapUrl().toLowerCase(Locale.ROOT).contains("ldaps://"))) {
            // sets ldaptive's thread-local TLS configuration, which SniJndiConnectionFactory captures
            factory = ThreadLocalTLSSocketFactory.getHostnameVerifierFactory(
                cc.getSslConfig(),
                new LdapURL(cc.getLdapUrl()).getHostnames()
            );
        }
        ClassLoader classLoader = config.getClassLoader();
        // plain LDAP has no socket factory, so JNDI has nothing to load
        if (classLoader == null && factory != null) {
            try {
                Thread.currentThread().getContextClassLoader().loadClass(factory.getClass().getName());
            } catch (ClassNotFoundException e) {
                classLoader = factory.getClass().getClassLoader();
            }
        }
        return new SniJndiConnectionFactory(
            cc.getLdapUrl(),
            cc.getConnectionStrategy(),
            config,
            environment(cc, env, factory),
            classLoader
        );
    }

    /**
     * The JNDI environment of the connections: {@code env} if the provider configuration sets one explicitly, otherwise
     * ldaptive's default for {@code cc}. The default registers {@code factory} as JNDI socket factory for LDAPS, unless the
     * provider properties (where both backends put {@link SNISettingTLSSocketFactory}) override it.
     */
    private Map<String, Object> environment(ConnectionConfig cc, Map<String, Object> env, SSLSocketFactory factory) {
        if (env != null) {
            return env;
        }
        String socketFactoryClass = factory == null ? null : factory.getClass().getName();
        return getDefaultEnvironment(cc, socketFactoryClass);
    }

    @Override
    public JndiProvider newInstance() {
        return new SniJndiProvider();
    }

    static final class SniJndiConnectionFactory extends JndiConnectionFactory {

        private final boolean isSniEnabled;
        private final SslConfig sslConfig;

        SniJndiConnectionFactory(
            String url,
            ConnectionStrategy strategy,
            JndiProviderConfig config,
            Map<String, Object> env,
            ClassLoader cl
        ) {
            super(url, strategy, config, env, cl);
            // true only for LDAPS with the SNI factory registered; compared by name so plain LDAP never loads the factory
            this.isSniEnabled = SocketFactoryClassLoader.SNI_SETTING_TLS_SOCKET_FACTORY.equals(env.get(SOCKET_FACTORY));
            this.sslConfig = isSniEnabled ? SNISettingTLSSocketFactory.currentSslConfig() : null;
        }

        /** ldaptive's TLS configuration this factory re-installs for every URL. Package-private for tests. */
        SslConfig sslConfig() {
            return sslConfig;
        }

        @Override
        protected JndiConnection createInternal(String url) throws LdapException {
            if (!isSniEnabled) {
                return super.createInternal(url);
            }
            try (var ignored = SNISettingTLSSocketFactory.configure(new LdapURL(url).getEntry().getHostname(), sslConfig)) {
                return super.createInternal(url);
            }
        }
    }
}
