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
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.StandardConstants;

import org.junit.After;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.ldap.util.ConfigConstants;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;

import org.ldaptive.Connection;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.LdapException;
import org.ldaptive.provider.ProviderConnection;
import org.ldaptive.provider.jndi.JndiProvider;
import org.ldaptive.ssl.AllowAnyTrustManager;
import org.ldaptive.ssl.SslConfig;
import org.ldaptive.ssl.ThreadLocalTLSSocketFactory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class SniJndiProviderTest {

    private static final String PASSWORD = SSLConfigConstants.DEFAULT_STORE_PASSWORD;

    @After
    public void clearThreadLocal() {
        SNISettingTLSSocketFactory.clearContext();
        new ThreadLocalTLSSocketFactory().setSslConfig(null);
    }

    @Test
    public void failover_sendsSniOfTheHostActuallyTried() throws Exception {
        List<String> receivedSni = new CopyOnWriteArrayList<>();
        try (SSLServerSocket server = sniRecordingServer(receivedSni)) {
            // .invalid never resolves (RFC 6761), so ldaptive moves on to localhost
            Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "ldap.invalid:" + server.getLocalPort(), "localhost:" + server.getLocalPort())
                .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, FileHelper.resolveStore("ldap/truststore").path())
                .put("path.home", ".")
                .build();
            Connection connection = new LDAPConnectionFactoryFactory(settings, null).createBasicConnectionFactory().getConnection();

            // the server only completes the TLS handshake and does not speak LDAP; without a bind, open() may still
            // succeed, as JNDI sends nothing before the first operation
            try {
                connection.open();
            } catch (LdapException e) {
                // irrelevant here, only the SNI received matters
            } finally {
                connection.close();
            }

            assertEquals(List.of("localhost"), receivedSni);
            assertNull(SNISettingTLSSocketFactory.getHostname());
        }
    }

    @Test
    public void connectionFactory_capturesSslConfigOfTheCreatingThread() {
        SslConfig sslConfig = new SslConfig();
        new ThreadLocalTLSSocketFactory().setSslConfig(sslConfig);

        SniJndiProvider.SniJndiConnectionFactory factory = connectionFactory(SNISettingTLSSocketFactory.class.getName());

        assertSame(sslConfig, factory.sslConfig());
    }

    @Test
    public void connectionFactory_withoutSniSocketFactory_capturesNothing() {
        new ThreadLocalTLSSocketFactory().setSslConfig(new SslConfig());

        assertNull(connectionFactory(ThreadLocalTLSSocketFactory.class.getName()).sslConfig());
    }

    // --- getJndiConnectionFactory: the same decisions as ldaptive's JndiProvider ---

    @Test
    public void ldapsUrl_ldaptiveSetsTlsConfig_andTheFactoryCapturesIt() {
        SniJndiProvider.SniJndiConnectionFactory factory = jndiConnectionFactory(
            sniProvider(),
            new ConnectionConfig("ldaps://localhost:636")
        );

        assertNotNull(SNISettingTLSSocketFactory.currentSslConfig());
        assertSame(SNISettingTLSSocketFactory.currentSslConfig(), factory.sslConfig());
    }

    @Test
    public void useSslOnLdapUrl_isTreatedAsLdaps() {
        ConnectionConfig cc = new ConnectionConfig("ldap://localhost:636");
        cc.setUseSSL(true);

        SniJndiProvider.SniJndiConnectionFactory factory = jndiConnectionFactory(sniProvider(), cc);

        assertNotNull(factory.sslConfig());
    }

    @Test
    public void plainLdap_leavesTlsConfigAlone() {
        SniJndiProvider.SniJndiConnectionFactory factory = jndiConnectionFactory(
            new SniJndiProvider(),
            new ConnectionConfig("ldap://localhost:389")
        );

        assertNull(SNISettingTLSSocketFactory.currentSslConfig());
        assertNull(factory.sslConfig());
    }

    @Test
    public void explicitSslSocketFactory_isUsedInsteadOfLdaptivesThreadLocalOne() throws Exception {
        SniJndiProvider provider = sniProvider();
        provider.getProviderConfig().setSslSocketFactory(SSLContext.getDefault().getSocketFactory());

        SniJndiProvider.SniJndiConnectionFactory factory = jndiConnectionFactory(provider, new ConnectionConfig("ldaps://localhost:636"));

        // ldaptive only sets its thread-local configuration when it builds the socket factory itself
        assertNull(SNISettingTLSSocketFactory.currentSslConfig());
        assertNull(factory.sslConfig());
    }

    @Test
    public void explicitEnvironment_replacesTheDefault() {
        SslConfig existing = new SslConfig();
        new ThreadLocalTLSSocketFactory().setSslConfig(existing);
        ConnectionConfig plainLdap = new ConnectionConfig("ldap://localhost:389");

        // the default environment of plain LDAP has no socket factory, so nothing is captured ...
        assertNull(jndiConnectionFactory(new SniJndiProvider(), plainLdap).sslConfig());
        // ... while an explicit one naming the SNI factory is used as is
        SniJndiProvider.SniJndiConnectionFactory factory = (SniJndiProvider.SniJndiConnectionFactory) new SniJndiProvider()
            .getJndiConnectionFactory(plainLdap, Map.of(JndiProvider.SOCKET_FACTORY, SNISettingTLSSocketFactory.class.getName()));
        assertSame(existing, factory.sslConfig());
    }

    @Test
    public void withoutClassLoader_fallsBackToTheSocketFactorysLoader_whenTheContextLoaderCannotSeeIt() throws Exception {
        List<String> receivedSni = new CopyOnWriteArrayList<>();
        try (SSLServerSocket server = sniRecordingServer(receivedSni)) {
            ConnectionConfig cc = new ConnectionConfig("ldaps://localhost:" + server.getLocalPort());
            SslConfig sslConfig = new SslConfig();
            sslConfig.setTrustManagers(new AllowAnyTrustManager());
            cc.setSslConfig(sslConfig);
            cc.setConnectTimeout(Duration.ofSeconds(5));

            // a context loader that sees neither ldaptive nor this plugin: JNDI can only load the socket factory if the
            // connection factory falls back to the loader of ldaptive's socket factory, as ldaptive itself does
            ClassLoader original = Thread.currentThread().getContextClassLoader();
            Thread.currentThread().setContextClassLoader(new ClassLoader(null) {
            });
            try {
                jndiConnectionFactory(sniProvider(), cc).create().close(null);
            } finally {
                Thread.currentThread().setContextClassLoader(original);
            }

            assertEquals(List.of("localhost"), receivedSni);
        }
    }

    @Test
    public void plainLdap_connectsWithoutSniContext() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            ConnectionConfig cc = new ConnectionConfig("ldap://localhost:" + server.getLocalPort());
            cc.setConnectTimeout(Duration.ofSeconds(5));
            SniJndiProvider.SniJndiConnectionFactory factory = jndiConnectionFactory(new SniJndiProvider(), cc);

            ProviderConnection connection = factory.create();
            try (Socket accepted = server.accept()) {
                assertTrue(accepted.isConnected());
                assertNull(SNISettingTLSSocketFactory.getHostname());
            } finally {
                connection.close(null);
            }
        }
    }

    @Test
    public void newInstance_isAnSniJndiProvider() {
        assertTrue(new SniJndiProvider().newInstance() instanceof SniJndiProvider);
    }

    /** A provider configured like the LDAP backends do: {@link SNISettingTLSSocketFactory} as JNDI socket factory. */
    private static SniJndiProvider sniProvider() {
        SniJndiProvider provider = new SniJndiProvider();
        provider.getProviderConfig().setProperties(Map.of(JndiProvider.SOCKET_FACTORY, SNISettingTLSSocketFactory.class.getName()));
        return provider;
    }

    private static SniJndiProvider.SniJndiConnectionFactory jndiConnectionFactory(SniJndiProvider provider, ConnectionConfig cc) {
        return (SniJndiProvider.SniJndiConnectionFactory) provider.getJndiConnectionFactory(cc, null);
    }

    private static SniJndiProvider.SniJndiConnectionFactory connectionFactory(String socketFactory) {
        SniJndiProvider provider = new SniJndiProvider();
        return new SniJndiProvider.SniJndiConnectionFactory(
            "ldaps://localhost:636",
            null,
            provider.getProviderConfig(),
            Map.of(JndiProvider.SOCKET_FACTORY, socketFactory),
            null
        );
    }

    /** TLS server on loopback that records the SNI host names of all handshakes until it is closed. */
    private static SSLServerSocket sniRecordingServer(List<String> receivedSni) throws Exception {
        KeyStore keyStore = FileHelper.getKeystoreFromClassPath("ldap/node-0-keystore", PASSWORD);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), null, null);

        SSLServerSocket server = (SSLServerSocket) context.getServerSocketFactory()
            .createServerSocket(0, 5, InetAddress.getLoopbackAddress());
        SSLParameters parameters = server.getSSLParameters();
        parameters.setSNIMatchers(List.of(new SNIMatcher(StandardConstants.SNI_HOST_NAME) {
            @Override
            public boolean matches(SNIServerName serverName) {
                receivedSni.add(((SNIHostName) serverName).getAsciiName());
                return true;
            }
        }));
        server.setSSLParameters(parameters);

        Thread.ofPlatform().name("sni-recording-server").daemon().start(() -> {
            while (!server.isClosed()) {
                try (SSLSocket socket = (SSLSocket) server.accept()) {
                    socket.startHandshake();
                } catch (Exception e) {
                    // closed by the test, or a failed handshake: only the SNI received matters
                }
            }
        });
        return server;
    }
}
