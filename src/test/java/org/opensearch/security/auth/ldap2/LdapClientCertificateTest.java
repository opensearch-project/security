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

import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.ldap.backend.LDAPAuthorizationBackend;
import org.opensearch.security.auth.ldap.util.ConfigConstants;
import org.opensearch.security.auth.ldap.util.Utils;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;

import org.ldaptive.Connection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

/**
 * Checks which client certificate the LDAP backends present over LDAPS. Run in FIPS mode, these tests also cover that
 * {@link LdapCredentialConfig} keeps ldaptive from copying the key store, which fails for BCFKS.
 */
public class LdapClientCertificateTest {

    private static final String PASSWORD = SSLConfigConstants.DEFAULT_STORE_PASSWORD;

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void ldap2_keystore_presentsCertAlias() throws Exception {
        for (String alias : List.of("kirk", "spock")) {
            assertOnlyPresented(certificate(alias), port -> {
                Settings settings = keystoreSettings(port, alias);
                openAndClose(new LDAPConnectionFactoryFactory(settings, null).createBasicConnectionFactory().getConnection());
            });
        }
    }

    @Test
    public void ldap2_pem_presentsPemCertificate() throws Exception {
        assertOnlyPresented(pemCertificate("ldap/spock.crt.pem"), port -> {
            Settings settings = baseSettings(port).put(ConfigConstants.LDAPS_PEMTRUSTEDCAS_FILEPATH, classpathFile("ldap/root-ca.pem"))
                .put(ConfigConstants.LDAPS_PEMCERT_FILEPATH, classpathFile("ldap/spock.crt.pem"))
                .put(ConfigConstants.LDAPS_PEMKEY_FILEPATH, classpathFile("ldap/spock.key.pem"))
                .build();
            openAndClose(new LDAPConnectionFactoryFactory(settings, null).createBasicConnectionFactory().getConnection());
        });
    }

    @Test
    public void ldap_keystore_presentsCertAlias() throws Exception {
        for (String alias : List.of("kirk", "spock")) {
            assertOnlyPresented(certificate(alias), port -> {
                try {
                    Utils.unbindAndCloseSilently(LDAPAuthorizationBackend.getConnection(keystoreSettings(port, alias), null));
                } catch (Exception e) {
                    // the server does not speak LDAP; only the certificate received matters
                }
            });
        }
    }

    @FunctionalInterface
    private interface ClientCall {
        void connect(int port) throws Exception;
    }

    /** Runs {@code call} against a fresh server and asserts every handshake presented exactly {@code expected}. */
    private static void assertOnlyPresented(X509Certificate expected, ClientCall call) throws Exception {
        List<X509Certificate> received = new CopyOnWriteArrayList<>();
        try (SSLServerSocket server = clientCertRecordingServer(received)) {
            call.connect(server.getLocalPort());
        }
        assertFalse("no client certificate received", received.isEmpty());
        for (X509Certificate certificate : received) {
            assertEquals(expected.getSubjectX500Principal(), certificate.getSubjectX500Principal());
        }
    }

    private Settings keystoreSettings(int port, String alias) throws Exception {
        KeyStore keyStore = keyStoreWithKirkAndSpock();
        Path file = tmp.getRoot().toPath().resolve("kirk-and-spock." + keyStore.getType().toLowerCase(Locale.ROOT));
        try (FileOutputStream out = new FileOutputStream(file.toFile())) {
            keyStore.store(out, PASSWORD.toCharArray());
        }
        FileHelper.TypedStore trustStore = FileHelper.resolveStore("ldap/truststore");
        return baseSettings(port).put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, trustStore.path().toString())
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE, trustStore.type())
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, file.toString())
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, keyStore.getType())
            .put(ConfigConstants.LDAPS_JKS_CERT_ALIAS, alias)
            .build();
    }

    private static Settings.Builder baseSettings(int port) {
        return Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + port)
            .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
            .put(ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH, true)
            .put("path.home", ".");
    }

    private static void openAndClose(Connection connection) {
        try {
            connection.open();
        } catch (Exception e) {
            // the server does not speak LDAP; only the certificate received matters
        } finally {
            connection.close();
        }
    }

    /** One key store holding the kirk and spock client keys, so only the alias decides which certificate is sent. */
    private static KeyStore keyStoreWithKirkAndSpock() throws Exception {
        KeyStore kirk = FileHelper.getKeystoreFromClassPath("ldap/kirk-keystore", PASSWORD);
        KeyStore spock = FileHelper.getKeystoreFromClassPath("ldap/spock-keystore", PASSWORD);
        KeyStore combined = KeyStore.getInstance(kirk.getType());
        combined.load(null, PASSWORD.toCharArray());
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(PASSWORD.toCharArray());
        combined.setEntry("kirk", kirk.getEntry("kirk", protection), protection);
        combined.setEntry("spock", spock.getEntry("spock", protection), protection);
        return combined;
    }

    private static X509Certificate certificate(String alias) throws Exception {
        return (X509Certificate) FileHelper.getKeystoreFromClassPath("ldap/" + alias + "-keystore", PASSWORD).getCertificate(alias);
    }

    private static X509Certificate pemCertificate(String resource) throws Exception {
        try (InputStream in = Files.newInputStream(FileHelper.getAbsoluteFilePathFromClassPath(resource))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    private static String classpathFile(String resource) {
        return FileHelper.getAbsoluteFilePathFromClassPath(resource).toString();
    }

    /**
     * TLS server on loopback that requires a client certificate and records the leaf of every chain it receives,
     * accepting any, until it is closed.
     */
    private static SSLServerSocket clientCertRecordingServer(List<X509Certificate> received) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(FileHelper.getKeystoreFromClassPath("ldap/node-0-keystore", PASSWORD), PASSWORD.toCharArray());
        TrustManager recordingTrustManager = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                received.add(chain[0]);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), new TrustManager[] { recordingTrustManager }, null);

        SSLServerSocket server = (SSLServerSocket) context.getServerSocketFactory()
            .createServerSocket(0, 5, InetAddress.getLoopbackAddress());
        server.setNeedClientAuth(true);
        Thread.ofPlatform().name("client-cert-recording-server").daemon().start(() -> {
            while (!server.isClosed()) {
                try (SSLSocket socket = (SSLSocket) server.accept()) {
                    socket.startHandshake();
                } catch (Exception e) {
                    // closed by the test, or a failed handshake: only the certificate received matters
                }
            }
        });
        return server;
    }
}
