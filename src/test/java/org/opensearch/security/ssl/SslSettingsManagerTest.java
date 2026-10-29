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

package org.opensearch.security.ssl;

import java.net.InetAddress;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import com.carrotsearch.randomizedtesting.RandomizedTest;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.env.TestEnvironment;
import org.opensearch.security.ssl.config.CertType;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.util.BCFipsEntropyDaemonFilter;
import org.opensearch.test.BouncyCastleThreadFilter;

import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.JdkSslContext;
import io.netty.handler.ssl.SslContext;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.ssl.CertificatesUtils.privateKeyToPemObject;
import static org.opensearch.security.ssl.CertificatesUtils.writePemContent;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_CLIENTAUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_KEYSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_HTTP_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_SERVER_EXTENDED_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.getStringAffixKeyForCertType;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SSL_ONLY;
import static org.opensearch.transport.AuxTransport.AUX_TRANSPORT_TYPES_SETTING;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

@ThreadLeakFilters(filters = { BouncyCastleThreadFilter.class, BCFipsEntropyDaemonFilter.class })
public class SslSettingsManagerTest extends RandomizedTest {

    @ClassRule
    public static CertificatesRule certificatesRule = new CertificatesRule();

    /*
    Settings for a mock aux transport - foo
     */
    private static final CertType MOCK_AUX_CERT_TYPE_FOO = new CertType("plugins.security.ssl.aux.foo.");
    private static final String MOCK_AUX_CERT_TYPE_FOO_PEMTRUSTEDCAS_FILEPATH = "plugins.security.ssl.aux.foo.pemtrustedcas_filepath";
    private static final String MOCK_AUX_CERT_TYPE_FOO_PEMCERT_FILEPATH = "plugins.security.ssl.aux.foo.pemcert_filepath";
    private static final String MOCK_AUX_CERT_TYPE_FOO_PEMKEY_FILEPATH = "plugins.security.ssl.aux.foo.pemkey_filepath";
    private static final String MOCK_AUX_CERT_TYPE_FOO_PEMTRUSTEDCAS_NAME = "ca_foo_certificate.pem";
    private static final String MOCK_AUX_CERT_TYPE_FOO_PEMCERT_NAME = "access_foo_certificate.pem";
    private static final String MOCK_AUX_CERT_TYPE_FOO_PEMKEY_NAME = "access_foo_certificate_pk.pem";
    private static final Settings ENABLE_FOO_SETTINGS_BUILDER = Settings.builder()
        .putList("aux.transport.types", List.of("foo"))
        .put("plugins.security.ssl.aux.foo.enabled", true)
        .build();

    /*
    Settings for a mock aux transport - bar
     */
    private static final CertType MOCK_AUX_CERT_TYPE_BAR = new CertType("plugins.security.ssl.aux.bar.");
    private static final String MOCK_AUX_CERT_TYPE_BAR_PEMTRUSTEDCAS_FILEPATH = "plugins.security.ssl.aux.bar.pemtrustedcas_filepath";
    private static final String MOCK_AUX_CERT_TYPE_BAR_PEMCERT_FILEPATH = "plugins.security.ssl.aux.bar.pemcert_filepath";
    private static final String MOCK_AUX_CERT_TYPE_BAR_PEMKEY_FILEPATH = "plugins.security.ssl.aux.bar.pemkey_filepath";
    private static final String MOCK_AUX_CERT_TYPE_BAR_PEMTRUSTEDCAS_NAME = "ca_bar_certificate.pem";
    private static final String MOCK_AUX_CERT_TYPE_BAR_PEMCERT_NAME = "access_bar_certificate.pem";
    private static final String MOCK_AUX_CERT_TYPE_BAR_PEMKEY_NAME = "access_bar_certificate_pk.pem";
    private static final Settings ENABLE_BAR_SETTINGS_BUILDER = Settings.builder()
        .putList("aux.transport.types", List.of("bar"))
        .put("plugins.security.ssl.aux.bar.enabled", true)
        .build();

    static Settings.Builder defaultSettingsBuilder() {
        return Settings.builder()
            .put(Environment.PATH_HOME_SETTING.getKey(), certificatesRule.configRootFolder().toString())
            .put("client.type", "node");
    }

    @Test
    public void configuredCipherListsAreNotExpanded() throws Exception {
        for (CertType certType : List.of(CertType.HTTP, CertType.TRANSPORT)) {
            for (List<String> ciphers : List.of(
                List.of("TLS_AES_128_GCM_SHA256"),
                List.of("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
                List.of("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
                List.of("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
            )) {
                final var settings = cipherSettings(certType).putList(certType.sslSettingPrefix() + "enabled_ciphers", ciphers).build();
                final var environment = TestEnvironment.newEnvironment(settings);
                final var configuration = new SslSettingsManager(environment).sslConfiguration(certType).orElseThrow();
                final var engine = configuration.buildServerSslContext(true).newEngine(UnpooledByteBufAllocator.DEFAULT);
                assertEquals(ciphers, List.of(engine.getEnabledCipherSuites()));
                final var legacy = new DefaultSecurityKeyStore(settings, environment.configDir());
                final var legacyEngine = certType == CertType.HTTP ? legacy.createHTTPSSLEngine() : legacy.createServerTransportSSLEngine();
                assertEquals(ciphers, List.of(legacyEngine.getEnabledCipherSuites()));
            }
        }
    }

    @Test
    public void defaultCipherListsIncludeHttp2Recommendations() {
        assertThat(
            "Defaults already include HTTP/2 ciphers",
            List.of(org.opensearch.security.ssl.util.SSLConfigConstants.ALLOWED_SSL_CIPHERS)
                .containsAll(io.netty.handler.codec.http2.Http2SecurityUtil.CIPHERS)
        );
        for (CertType certType : List.of(CertType.HTTP, CertType.TRANSPORT)) {
            final var configuration = new SslSettingsManager(TestEnvironment.newEnvironment(cipherSettings(certType).build()))
                .sslConfiguration(certType)
                .orElseThrow();
            final var engine = configuration.buildServerSslContext(true).newEngine(UnpooledByteBufAllocator.DEFAULT);
            assertEquals(
                new TreeSet<>(configuration.sslParameters().allowedCiphers()),
                new TreeSet<>(List.of(engine.getEnabledCipherSuites()))
            );
        }
    }

    private Settings.Builder cipherSettings(CertType certType) {
        final var securitySettings = new MockSecureSettings();
        securitySettings.setString(SSL_HTTP_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(SSL_TRANSPORT_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        return defaultSettingsBuilder().setSecureSettings(securitySettings)
            .put(httpSslSettings().build())
            .put(transportSslSettings().build())
            .put(SECURITY_SSL_TRANSPORT_ENABLED, certType == CertType.TRANSPORT)
            .put(SECURITY_SSL_ONLY, true);
    }

    @Test
    public void tls13HandshakeHonorsConfiguredCiphers() throws Exception {
        for (CertType certType : List.of(CertType.HTTP, CertType.TRANSPORT)) {
            final var settings = defaultSettingsBuilder().put(SECURITY_SSL_ONLY, true)
                .put(SECURITY_SSL_HTTP_ENABLED, certType == CertType.HTTP)
                .put(SECURITY_SSL_TRANSPORT_ENABLED, certType == CertType.TRANSPORT)
                .put(certType.sslSettingPrefix() + "keystore_filepath", FileHelper.resolveStore("ssl/node-0-keystore").path())
                .put(certType.sslSettingPrefix() + "truststore_filepath", FileHelper.resolveStore("ssl/truststore").path())
                .putList(certType.sslSettingPrefix() + "enabled_protocols", "TLSv1.3")
                .putList(certType.sslSettingPrefix() + "enabled_ciphers", "TLS_AES_128_GCM_SHA256")
                .build();
            final var configuration = new SslSettingsManager(TestEnvironment.newEnvironment(settings)).sslConfiguration(certType)
                .orElseThrow();
            final var serverContext = (JdkSslContext) configuration.buildServerSslContext(true);
            final var clientContext = (JdkSslContext) configuration.buildClientSslContext(true);
            for (String cipher : List.of("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256")) {
                // ChaCha is unavailable with FIPS providers; still exercise the AES-only restriction there.
                if (cipher.equals("TLS_CHACHA20_POLY1305_SHA256")
                    && !List.of(clientContext.context().getSupportedSSLParameters().getCipherSuites()).contains(cipher)) {
                    continue;
                }
                boolean allowed = cipher.equals("TLS_AES_128_GCM_SHA256");
                try (
                    var executor = Executors.newSingleThreadExecutor();
                    var server = (SSLServerSocket) serverContext.context()
                        .getServerSocketFactory()
                        .createServerSocket(0, 1, InetAddress.getLoopbackAddress())
                ) {
                    server.setSoTimeout(10000);
                    server.setEnabledProtocols(new String[] { "TLSv1.3" });
                    server.setEnabledCipherSuites(serverContext.cipherSuites().toArray(String[]::new));
                    server.setNeedClientAuth(certType == CertType.TRANSPORT);
                    final var handshake = executor.submit(() -> {
                        try (var socket = (SSLSocket) server.accept()) {
                            socket.setSoTimeout(10000);
                            socket.startHandshake();
                            return socket.getSession().getCipherSuite();
                        } catch (SSLHandshakeException e) {
                            return null;
                        }
                    });
                    try (
                        var client = (SSLSocket) clientContext.context()
                            .getSocketFactory()
                            .createSocket(InetAddress.getLoopbackAddress(), server.getLocalPort())
                    ) {
                        client.setSoTimeout(10000);
                        client.setEnabledProtocols(new String[] { "TLSv1.3" });
                        client.setEnabledCipherSuites(new String[] { cipher });
                        if (allowed) {
                            client.startHandshake();
                            assertEquals(cipher, handshake.get(15, TimeUnit.SECONDS));
                        } else {
                            assertThrows(SSLHandshakeException.class, client::startHandshake);
                            assertNull(handshake.get(15, TimeUnit.SECONDS));
                        }
                    }
                }
            }
        }
    }

    @Test
    public void defaultTls12HandshakePrefersEcdheGcm() throws Exception {
        for (CertType certType : List.of(CertType.HTTP, CertType.TRANSPORT)) {
            final var settings = defaultSettingsBuilder().put(SECURITY_SSL_ONLY, true)
                .put(SECURITY_SSL_HTTP_ENABLED, certType == CertType.HTTP)
                .put(SECURITY_SSL_TRANSPORT_ENABLED, certType == CertType.TRANSPORT)
                .put(certType.sslSettingPrefix() + "keystore_filepath", FileHelper.resolveStore("ssl/node-0-keystore").path())
                .put(certType.sslSettingPrefix() + "truststore_filepath", FileHelper.resolveStore("ssl/truststore").path())
                .build();
            final var configuration = new SslSettingsManager(TestEnvironment.newEnvironment(settings)).sslConfiguration(certType)
                .orElseThrow();
            final var serverContext = (JdkSslContext) configuration.buildServerSslContext(true);
            final var clientContext = (JdkSslContext) configuration.buildClientSslContext(true);
            try (
                var executor = Executors.newSingleThreadExecutor();
                var server = (SSLServerSocket) serverContext.context()
                    .getServerSocketFactory()
                    .createServerSocket(0, 1, InetAddress.getLoopbackAddress())
            ) {
                server.setSoTimeout(10000);
                server.setEnabledCipherSuites(serverContext.cipherSuites().toArray(String[]::new));
                server.setNeedClientAuth(certType == CertType.TRANSPORT);
                final var handshake = executor.submit(() -> {
                    try (var socket = (SSLSocket) server.accept()) {
                        socket.setSoTimeout(10000);
                        socket.startHandshake();
                        return socket.getSession().getCipherSuite();
                    }
                });
                try (
                    var client = (SSLSocket) clientContext.context()
                        .getSocketFactory()
                        .createSocket(InetAddress.getLoopbackAddress(), server.getLocalPort())
                ) {
                    client.setSoTimeout(10000);
                    client.setEnabledProtocols(new String[] { "TLSv1.2" });
                    // Leave the client's default cipher list intact to exercise server preference.
                    client.startHandshake();
                    assertEquals("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", client.getSession().getCipherSuite());
                    assertEquals(client.getSession().getCipherSuite(), handshake.get(15, TimeUnit.SECONDS));
                }
            }
        }
    }

    private Settings.Builder transportSslSettings() {
        return Settings.builder()
            .put("plugins.security.ssl.transport.enabled", true)
            .put("plugins.security.ssl.transport.pemtrustedcas_filepath", path("ca_transport_certificate.pem"))
            .put("plugins.security.ssl.transport.pemcert_filepath", path("access_transport_certificate.pem"))
            .put("plugins.security.ssl.transport.pemkey_filepath", path("access_transport_certificate_pk.pem"));
    }

    private Settings.Builder httpSslSettings() {
        return Settings.builder()
            .put("plugins.security.ssl.transport.enabled", true)
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.pemtrustedcas_filepath", path("ca_http_certificate.pem"))
            .put("plugins.security.ssl.http.pemcert_filepath", path("access_http_certificate.pem"))
            .put("plugins.security.ssl.http.pemkey_filepath", path("access_http_certificate_pk.pem"));
    }

    private Settings.Builder auxFooSslSettings() {
        return Settings.builder()
            .put(ENABLE_FOO_SETTINGS_BUILDER)
            .put(MOCK_AUX_CERT_TYPE_FOO_PEMTRUSTEDCAS_FILEPATH, path(MOCK_AUX_CERT_TYPE_FOO_PEMTRUSTEDCAS_NAME))
            .put(MOCK_AUX_CERT_TYPE_FOO_PEMCERT_FILEPATH, path(MOCK_AUX_CERT_TYPE_FOO_PEMCERT_NAME))
            .put(MOCK_AUX_CERT_TYPE_FOO_PEMKEY_FILEPATH, path(MOCK_AUX_CERT_TYPE_FOO_PEMKEY_NAME));
    }

    private Settings.Builder auxBarSslSettings() {
        return Settings.builder()
            .put(ENABLE_BAR_SETTINGS_BUILDER)
            .put(MOCK_AUX_CERT_TYPE_BAR_PEMTRUSTEDCAS_FILEPATH, path(MOCK_AUX_CERT_TYPE_BAR_PEMTRUSTEDCAS_NAME))
            .put(MOCK_AUX_CERT_TYPE_BAR_PEMCERT_FILEPATH, path(MOCK_AUX_CERT_TYPE_BAR_PEMCERT_NAME))
            .put(MOCK_AUX_CERT_TYPE_BAR_PEMKEY_FILEPATH, path(MOCK_AUX_CERT_TYPE_BAR_PEMKEY_NAME));
    }

    @BeforeClass
    public static void setUp() throws Exception {
        writeCertificates("ca_http_certificate.pem", "access_http_certificate.pem", "access_http_certificate_pk.pem");
        writeCertificates("ca_transport_certificate.pem", "access_transport_certificate.pem", "access_transport_certificate_pk.pem");
        writeCertificates(
            "ca_" + MOCK_AUX_CERT_TYPE_FOO.id() + "_certificate.pem",
            "access_" + MOCK_AUX_CERT_TYPE_FOO.id() + "_certificate.pem",
            "access_" + MOCK_AUX_CERT_TYPE_FOO.id() + "_certificate_pk.pem"
        );
        writeCertificates(
            "ca_" + MOCK_AUX_CERT_TYPE_BAR.id() + "_certificate.pem",
            "access_" + MOCK_AUX_CERT_TYPE_BAR.id() + "_certificate.pem",
            "access_" + MOCK_AUX_CERT_TYPE_BAR.id() + "_certificate_pk.pem"
        );
    }

    static void writeCertificates(final String trustedFileName, final String accessFileName, final String accessPkFileName)
        throws Exception {
        writePemContent(path(trustedFileName), certificatesRule.caCertificateHolder());
        writePemContent(path(accessFileName), certificatesRule.accessCertificateHolder());
        writePemContent(
            path(accessPkFileName),
            privateKeyToPemObject(certificatesRule.accessCertificatePrivateKey(), certificatesRule.privateKeyPassword())
        );
    }

    static Path path(final String fileName) {
        return certificatesRule.configRootFolder().resolve(fileName);
    }

    @Test
    public void failsIfNoSslSet() {
        final var settings = defaultSettingsBuilder().build();
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(settings)));
    }

    @Test
    public void testFailsIfNoConfigDefine() {
        assertThrows(
            OpenSearchException.class,
            () -> new SslSettingsManager(
                TestEnvironment.newEnvironment(defaultSettingsBuilder().put(SECURITY_SSL_HTTP_ENABLED, true).build())
            )
        );
        assertThrows(
            OpenSearchException.class,
            () -> new SslSettingsManager(
                TestEnvironment.newEnvironment(defaultSettingsBuilder().put(SECURITY_SSL_TRANSPORT_ENABLED, true).build())
            )
        );
        assertThrows(
            OpenSearchException.class,
            () -> new SslSettingsManager(TestEnvironment.newEnvironment(defaultSettingsBuilder().put(ENABLE_FOO_SETTINGS_BUILDER).build()))
        );
        assertThrows(
            OpenSearchException.class,
            () -> new SslSettingsManager(TestEnvironment.newEnvironment(defaultSettingsBuilder().put(ENABLE_BAR_SETTINGS_BUILDER).build()))
        );
    }

    @Test
    public void transportFailsIfJdkTrustStoreHasNotBeenSet() {
        final var noTransportSettingsButItEnabled = defaultSettingsBuilder().put(SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, certificatesRule.configRootFolder().toString())
            .build();
        assertThrows(
            OpenSearchException.class,
            () -> new SslSettingsManager(TestEnvironment.newEnvironment(noTransportSettingsButItEnabled))
        );
    }

    @Test
    public void transportFailsIfExtendedKeyUsageEnabledForJdkKeyStoreButNotConfigured() {
        final var noTransportSettingsButItEnabled = defaultSettingsBuilder().put(SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, certificatesRule.configRootFolder().toString())
            .put(SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, certificatesRule.configRootFolder().toString())
            .put(SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED, true)
            .build();
        assertThrows(
            OpenSearchException.class,
            () -> new SslSettingsManager(TestEnvironment.newEnvironment(noTransportSettingsButItEnabled))
        );
    }

    @Test
    public void transportFailsIfExtendedKeyUsageEnabledForPemKeyStoreButNotConfigured() {
        final var noTransportSettingsButItEnabled = defaultSettingsBuilder().put(SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, certificatesRule.configRootFolder().toString())
            .put(SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, certificatesRule.configRootFolder().toString())
            .put(SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED, true)
            .build();
        assertThrows(
            OpenSearchException.class,
            () -> new SslSettingsManager(TestEnvironment.newEnvironment(noTransportSettingsButItEnabled))
        );
    }

    @Test
    public void transportFailsIfConfigDisabled() {
        Settings settings = defaultSettingsBuilder().put(SECURITY_SSL_HTTP_ENABLED, true)
            .put(SECURITY_SSL_TRANSPORT_ENABLED, false)
            .build();
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(settings)));
    }

    /**
     * Security plugin enforces common store type for a single transport configuration.
     * Pem store and JKS (Java KeyStore) cannot both be used for transport.
     */
    private void configFailsIfBothPemAndJDKSettingsWereSet(
        Settings.Builder settingsBuilder,
        List<String> transportJKSSettings,
        List<String> transportPemStoreSettings
    ) {
        Settings settings = settingsBuilder.put(randomFrom(transportJKSSettings), "aaa")
            .put(randomFrom(transportPemStoreSettings), "bbb")
            .build();
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(settings)));
    }

    @Test
    public void configFailsIfBothPemAndJDKSettingsWereSet() {
        configFailsIfBothPemAndJDKSettingsWereSet(
            defaultSettingsBuilder().put(SECURITY_SSL_HTTP_ENABLED, true),
            List.of(SECURITY_SSL_HTTP_KEYSTORE_FILEPATH),
            List.of(SECURITY_SSL_HTTP_PEMKEY_FILEPATH, SECURITY_SSL_HTTP_PEMCERT_FILEPATH, SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH)
        );
        configFailsIfBothPemAndJDKSettingsWereSet(
            defaultSettingsBuilder().put(SECURITY_SSL_TRANSPORT_ENABLED, true),
            List.of(SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH),
            List.of(
                SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH,
                SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH,
                SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH
            )
        );
        configFailsIfBothPemAndJDKSettingsWereSet(
            defaultSettingsBuilder().put(ENABLE_FOO_SETTINGS_BUILDER),
            List.of(getStringAffixKeyForCertType(SECURITY_SSL_AUX_KEYSTORE_FILEPATH, MOCK_AUX_CERT_TYPE_FOO)),
            List.of(
                getStringAffixKeyForCertType(SECURITY_SSL_AUX_PEMKEY_FILEPATH, MOCK_AUX_CERT_TYPE_FOO),
                getStringAffixKeyForCertType(SECURITY_SSL_AUX_PEMCERT_FILEPATH, MOCK_AUX_CERT_TYPE_FOO),
                getStringAffixKeyForCertType(SECURITY_SSL_AUX_PEMTRUSTEDCAS_FILEPATH, MOCK_AUX_CERT_TYPE_FOO)
            )
        );
    }

    private void configFailsIfClientAuthRequiredAndJdkTrustStoreNotSet(
        Settings.Builder settingsBuilder,
        String clientAuthEnabledSetting,
        String keystorePathSetting
    ) {
        Settings settings = settingsBuilder.put(clientAuthEnabledSetting, ClientAuth.REQUIRE.name().toLowerCase(Locale.ROOT))
            .put(keystorePathSetting, certificatesRule.configRootFolder().toString())
            .build();
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(settings)));
    }

    @Test
    public void serverTransportConfigFailsIfClientAuthRequiredAndJdkTrustStoreNotSet() {
        configFailsIfClientAuthRequiredAndJdkTrustStoreNotSet(
            defaultSettingsBuilder().put(SECURITY_SSL_HTTP_ENABLED, true),
            SECURITY_SSL_HTTP_CLIENTAUTH_MODE,
            SECURITY_SSL_HTTP_KEYSTORE_FILEPATH
        );
        configFailsIfClientAuthRequiredAndJdkTrustStoreNotSet(
            defaultSettingsBuilder().put(ENABLE_FOO_SETTINGS_BUILDER),
            getStringAffixKeyForCertType(SECURITY_SSL_AUX_CLIENTAUTH_MODE, MOCK_AUX_CERT_TYPE_FOO),
            getStringAffixKeyForCertType(SECURITY_SSL_AUX_KEYSTORE_FILEPATH, MOCK_AUX_CERT_TYPE_FOO)
        );
    }

    private void configFailsIfClientAuthRequiredAndPemTrustedCasNotSet(
        Settings.Builder settingsBuilder,
        String clientAuthEnabledSetting,
        String pemkeyPathSetting,
        String pemcertPathSetting
    ) {
        Settings settings = settingsBuilder.put(clientAuthEnabledSetting, ClientAuth.REQUIRE.name().toLowerCase(Locale.ROOT))
            .put(pemkeyPathSetting, "aaa")
            .put(pemcertPathSetting, "bbb")
            .build();
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(settings)));
    }

    @Test
    public void serverTransportConfigFailsIfClientAuthRequiredAndPemTrustedCasNotSet() {
        configFailsIfClientAuthRequiredAndPemTrustedCasNotSet(
            defaultSettingsBuilder().put(SECURITY_SSL_HTTP_ENABLED, true),
            SECURITY_SSL_HTTP_CLIENTAUTH_MODE,
            SECURITY_SSL_HTTP_PEMKEY_FILEPATH,
            SECURITY_SSL_HTTP_PEMCERT_FILEPATH
        );
        configFailsIfClientAuthRequiredAndPemTrustedCasNotSet(
            defaultSettingsBuilder().put(ENABLE_FOO_SETTINGS_BUILDER),
            getStringAffixKeyForCertType(SECURITY_SSL_AUX_CLIENTAUTH_MODE, MOCK_AUX_CERT_TYPE_FOO),
            getStringAffixKeyForCertType(SECURITY_SSL_AUX_PEMKEY_FILEPATH, MOCK_AUX_CERT_TYPE_FOO),
            getStringAffixKeyForCertType(SECURITY_SSL_AUX_PEMCERT_FILEPATH, MOCK_AUX_CERT_TYPE_FOO)
        );
    }

    @Test
    public void loadConfigurationAndBuildSslContextForSslOnlyMode() {
        final var securitySettings = new MockSecureSettings();
        securitySettings.setString(SSL_TRANSPORT_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(SSL_HTTP_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(
            MOCK_AUX_CERT_TYPE_FOO.sslSettingPrefix() + "pemkey_password_secure",
            certificatesRule.privateKeyPassword()
        );
        final var settingsBuilder = defaultSettingsBuilder().setSecureSettings(securitySettings)
            .put(transportSslSettings().build())
            .put(httpSslSettings().build())
            .put(auxFooSslSettings().build());

        final var transportEnabled = randomBoolean();
        final var sslSettingsManager = new SslSettingsManager(
            TestEnvironment.newEnvironment(
                settingsBuilder.put(SECURITY_SSL_TRANSPORT_ENABLED, transportEnabled).put(SECURITY_SSL_ONLY, true).build()
            )
        );
        assertThat("Loaded HTTP configuration", sslSettingsManager.sslConfiguration(CertType.HTTP).isPresent());
        assertThat("Loaded AUX FOO configuration", sslSettingsManager.sslConfiguration(MOCK_AUX_CERT_TYPE_FOO).isPresent());
        if (transportEnabled) {
            assertThat("Loaded Transport configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT).isPresent());
            assertThat("Loaded Transport Client configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT).isPresent());
        } else {
            assertThat("Didn't load Transport configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT).isEmpty());
            assertThat(
                "Didn't load Transport Client configuration",
                sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT).isEmpty()
            );
        }
        assertThat("Built HTTP SSL Context", sslSettingsManager.sslContextHandler(CertType.HTTP).isPresent());
        assertThat("Built AUX FOO SSL Context", sslSettingsManager.sslContextHandler(MOCK_AUX_CERT_TYPE_FOO).isPresent());
        if (transportEnabled) {
            assertThat("Built Transport SSL Context", sslSettingsManager.sslContextHandler(CertType.TRANSPORT).isPresent());
            assertThat("Built Client SSL Context", sslSettingsManager.sslContextHandler(CertType.TRANSPORT_CLIENT).isPresent());
        } else {
            assertThat("Didn't build Transport SSL Context", sslSettingsManager.sslContextHandler(CertType.TRANSPORT).isEmpty());
            assertThat("Didn't build Client SSL Context", sslSettingsManager.sslContextHandler(CertType.TRANSPORT_CLIENT).isEmpty());
        }
        assertThat(
            "Built Server SSL context for HTTP",
            sslSettingsManager.sslContextHandler(CertType.HTTP).map(SslContextHandler::sslContext).map(SslContext::isServer).orElse(false)
        );
        assertThat(
            "Built Server SSL context for AUX FOO",
            sslSettingsManager.sslContextHandler(MOCK_AUX_CERT_TYPE_FOO)
                .map(SslContextHandler::sslContext)
                .map(SslContext::isServer)
                .orElse(false)
        );
    }

    @Test
    public void loadConfigurationAndBuildSslContextForClientNode() {
        final var securitySettings = new MockSecureSettings();
        securitySettings.setString(SSL_TRANSPORT_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(SSL_HTTP_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        final var settingsBuilder = defaultSettingsBuilder().setSecureSettings(securitySettings)
            .put(transportSslSettings().build())
            .put(httpSslSettings().build());
        final var sslSettingsManager = new SslSettingsManager(
            TestEnvironment.newEnvironment(
                settingsBuilder.put("client.type", "client").put(SECURITY_SSL_HTTP_ENABLED, randomBoolean()).build()
            )
        );
        assertThat("Didn't load HTTP configuration", sslSettingsManager.sslConfiguration(CertType.HTTP).isEmpty());
        assertThat("Loaded Transport configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT).isPresent());
        assertThat("Loaded Transport Client configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT).isPresent());
        assertThat("Didn't build HTTP SSL Context", sslSettingsManager.sslContextHandler(CertType.HTTP).isEmpty());
        assertThat("Built Transport SSL Context", sslSettingsManager.sslContextHandler(CertType.TRANSPORT).isPresent());
        assertThat("Built Client SSL Context", sslSettingsManager.sslContextHandler(CertType.TRANSPORT_CLIENT).isPresent());
        assertThat(
            "Built Server SSL context for Transport",
            sslSettingsManager.sslContextHandler(CertType.TRANSPORT)
                .map(SslContextHandler::sslContext)
                .map(SslContext::isServer)
                .orElse(false)
        );
        assertThat(
            "Built Client SSL context for Transport Client",
            sslSettingsManager.sslContextHandler(CertType.TRANSPORT_CLIENT)
                .map(SslContextHandler::sslContext)
                .map(SslContext::isClient)
                .orElse(false)

        );
    }

    @Test
    public void loadConfigurationAndBuildSslContextsMultipleAuxTransports() {
        final var securitySettings = new MockSecureSettings();
        securitySettings.setString(SSL_TRANSPORT_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(SSL_HTTP_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(
            MOCK_AUX_CERT_TYPE_FOO.sslSettingPrefix() + "pemkey_password_secure",
            certificatesRule.privateKeyPassword()
        );
        securitySettings.setString(
            MOCK_AUX_CERT_TYPE_BAR.sslSettingPrefix() + "pemkey_password_secure",
            certificatesRule.privateKeyPassword()
        );
        final var settingsBuilder = defaultSettingsBuilder().setSecureSettings(securitySettings)
            .put(transportSslSettings().build())
            .put(httpSslSettings().build())
            .put(auxBarSslSettings().build())
            .put(auxFooSslSettings().build());
        settingsBuilder.put(
            Settings.builder()
                .putList(AUX_TRANSPORT_TYPES_SETTING.getKey(), List.of(MOCK_AUX_CERT_TYPE_BAR.id(), MOCK_AUX_CERT_TYPE_FOO.id()))
                .build()
        );
        final var sslSettingsManager = new SslSettingsManager(TestEnvironment.newEnvironment(settingsBuilder.build()));
        assertThat("Loaded HTTP configuration", sslSettingsManager.sslConfiguration(CertType.HTTP).isPresent());
        assertThat("Loaded AUX FOO configuration", sslSettingsManager.sslConfiguration(MOCK_AUX_CERT_TYPE_FOO).isPresent());
        assertThat("Loaded AUX BAR configuration", sslSettingsManager.sslConfiguration(MOCK_AUX_CERT_TYPE_BAR).isPresent());
        assertThat("Loaded Transport configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT).isPresent());
        assertThat("Loaded Transport Client configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT).isPresent());
        assertThat(
            "Built Server SSL context for HTTP",
            sslSettingsManager.sslContextHandler(CertType.HTTP).map(SslContextHandler::sslContext).map(SslContext::isServer).orElse(false)
        );
        assertThat(
            "Built Server SSL context for AUX",
            sslSettingsManager.sslContextHandler(MOCK_AUX_CERT_TYPE_FOO)
                .map(SslContextHandler::sslContext)
                .map(SslContext::isServer)
                .orElse(false)
        );
        assertThat(
            "Built Server SSL context for AUX",
            sslSettingsManager.sslContextHandler(MOCK_AUX_CERT_TYPE_BAR)
                .map(SslContextHandler::sslContext)
                .map(SslContext::isServer)
                .orElse(false)
        );
        assertThat(
            "Built Server SSL context for Transport",
            sslSettingsManager.sslContextHandler(CertType.TRANSPORT)
                .map(SslContextHandler::sslContext)
                .map(SslContext::isServer)
                .orElse(false)
        );
        assertThat(
            "Built Client SSL context for Transport Client",
            sslSettingsManager.sslContextHandler(CertType.TRANSPORT_CLIENT)
                .map(SslContextHandler::sslContext)
                .map(SslContext::isClient)
                .orElse(false)

        );
    }

    @Test
    public void loadConfigurationAndBuildSslContexts() {
        final var securitySettings = new MockSecureSettings();
        securitySettings.setString(SSL_TRANSPORT_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(SSL_HTTP_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(
            MOCK_AUX_CERT_TYPE_FOO.sslSettingPrefix() + "pemkey_password_secure",
            certificatesRule.privateKeyPassword()
        );
        final var settingsBuilder = defaultSettingsBuilder().setSecureSettings(securitySettings)
            .put(transportSslSettings().build())
            .put(httpSslSettings().build())
            .put(auxFooSslSettings().build());
        final var sslSettingsManager = new SslSettingsManager(TestEnvironment.newEnvironment(settingsBuilder.build()));
        assertThat("Loaded HTTP configuration", sslSettingsManager.sslConfiguration(CertType.HTTP).isPresent());
        assertThat("Loaded AUX FOO configuration", sslSettingsManager.sslConfiguration(MOCK_AUX_CERT_TYPE_FOO).isPresent());
        assertThat("Loaded Transport configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT).isPresent());
        assertThat("Loaded Transport Client configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT).isPresent());
        assertThat(
            "Built Server SSL context for HTTP",
            sslSettingsManager.sslContextHandler(CertType.HTTP).map(SslContextHandler::sslContext).map(SslContext::isServer).orElse(false)
        );
        assertThat(
            "Built Server SSL context for AUX",
            sslSettingsManager.sslContextHandler(MOCK_AUX_CERT_TYPE_FOO)
                .map(SslContextHandler::sslContext)
                .map(SslContext::isServer)
                .orElse(false)
        );
        assertThat(
            "Built Server SSL context for Transport",
            sslSettingsManager.sslContextHandler(CertType.TRANSPORT)
                .map(SslContextHandler::sslContext)
                .map(SslContext::isServer)
                .orElse(false)
        );
        assertThat(
            "Built Client SSL context for Transport Client",
            sslSettingsManager.sslContextHandler(CertType.TRANSPORT_CLIENT)
                .map(SslContextHandler::sslContext)
                .map(SslContext::isClient)
                .orElse(false)

        );
    }

    @Test
    public void loadConfigurationAndBuildTransportSslContext() {
        final var securitySettings = new MockSecureSettings();
        securitySettings.setString(SSL_TRANSPORT_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        final var settingsBuilder = defaultSettingsBuilder().setSecureSettings(securitySettings).put(transportSslSettings().build());
        final var sslSettingsManager = new SslSettingsManager(TestEnvironment.newEnvironment(settingsBuilder.build()));
        assertThat("Didn't load HTTP configuration", sslSettingsManager.sslConfiguration(CertType.HTTP).isEmpty());
        assertThat("Didn't load AUX configuration", sslSettingsManager.sslConfiguration(MOCK_AUX_CERT_TYPE_FOO).isEmpty());
        assertThat("Loaded Transport configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT).isPresent());
        assertThat("Loaded Transport Client configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT).isPresent());
        assertThat(
            "SSL configuration for Transport and Transport Client is the same",
            sslSettingsManager.sslConfiguration(CertType.TRANSPORT)
                .flatMap(t -> sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT).map(tc -> tc.equals(t)))
                .orElse(false)
        );
        assertThat("Built HTTP SSL Context", sslSettingsManager.sslContextHandler(CertType.HTTP).isEmpty());
        assertThat("Built AUX SSL Context", sslSettingsManager.sslContextHandler(MOCK_AUX_CERT_TYPE_FOO).isEmpty());
        assertThat("Built Transport SSL Context", sslSettingsManager.sslContextHandler(CertType.TRANSPORT).isPresent());
        assertThat("Built Transport Client SSL Context", sslSettingsManager.sslContextHandler(CertType.TRANSPORT_CLIENT).isPresent());
        assertThat(
            "Built Server SSL context for Transport",
            sslSettingsManager.sslContextHandler(CertType.TRANSPORT)
                .map(SslContextHandler::sslContext)
                .map(SslContext::isServer)
                .orElse(false)

        );
        assertThat(
            "Built Client SSL context for Transport Client",
            sslSettingsManager.sslContextHandler(CertType.TRANSPORT_CLIENT)
                .map(SslContextHandler::sslContext)
                .map(SslContext::isClient)
                .orElse(false)

        );
    }

    @Test
    public void loadConfigurationAndBuildExtendedTransportSslContexts() throws Exception {
        writeCertificates(
            "ca_server_transport_certificate.pem",
            "access_server_transport_certificate.pem",
            "access_server_transport_certificate_pk.pem"
        );
        writeCertificates(
            "ca_client_transport_certificate.pem",
            "access_client_transport_certificate.pem",
            "access_client_transport_certificate_pk.pem"
        );
        final var securitySettings = new MockSecureSettings();
        securitySettings.setString(
            SSL_TRANSPORT_PREFIX + SSL_TRANSPORT_SERVER_EXTENDED_PREFIX + "pemkey_password_secure",
            certificatesRule.privateKeyPassword()
        );
        securitySettings.setString(
            SSL_TRANSPORT_PREFIX + SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX + "pemkey_password_secure",
            certificatesRule.privateKeyPassword()
        );

        final var sslSettingsManager = new SslSettingsManager(
            TestEnvironment.newEnvironment(
                defaultSettingsBuilder().put(SECURITY_SSL_TRANSPORT_ENABLED, true)
                    .put(SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED, true)
                    .put(SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH, path("ca_server_transport_certificate.pem"))
                    .put(SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH, path("access_server_transport_certificate.pem"))
                    .put(SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH, path("access_server_transport_certificate_pk.pem"))
                    .put(SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH, path("ca_client_transport_certificate.pem"))
                    .put(SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH, path("access_client_transport_certificate.pem"))
                    .put(SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH, path("access_client_transport_certificate_pk.pem"))
                    .setSecureSettings(securitySettings)
                    .build()
            )
        );

        assertThat("Didn't load HTTP configuration", sslSettingsManager.sslConfiguration(CertType.HTTP).isEmpty());
        assertThat("Didn't load AUX configuration", sslSettingsManager.sslConfiguration(MOCK_AUX_CERT_TYPE_FOO).isEmpty());
        assertThat("Loaded Transport configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT).isPresent());
        assertThat("Loaded Transport Client configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT).isPresent());
        assertThat(
            "SSL configuration for Transport and Transport Client is not the same",
            sslSettingsManager.sslConfiguration(CertType.TRANSPORT)
                .flatMap(t -> sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT).map(tc -> !tc.equals(t)))
                .orElse(true)
        );
        assertThat("Built HTTP SSL Context", sslSettingsManager.sslContextHandler(CertType.HTTP).isEmpty());
        assertThat("Built AUX SSL Context", sslSettingsManager.sslContextHandler(MOCK_AUX_CERT_TYPE_FOO).isEmpty());
        assertThat("Built Transport SSL Context", sslSettingsManager.sslContextHandler(CertType.TRANSPORT).isPresent());
        assertThat("Built Transport Client SSL Context", sslSettingsManager.sslContextHandler(CertType.TRANSPORT_CLIENT).isPresent());
        assertThat(
            "Built Server SSL context for Transport",
            sslSettingsManager.sslContextHandler(CertType.TRANSPORT)
                .map(SslContextHandler::sslContext)
                .map(SslContext::isServer)
                .orElse(false)

        );
        assertThat(
            "Built Client SSL context for Transport Client",
            sslSettingsManager.sslContextHandler(CertType.TRANSPORT_CLIENT)
                .map(SslContextHandler::sslContext)
                .map(SslContext::isClient)
                .orElse(false)

        );
    }
}
