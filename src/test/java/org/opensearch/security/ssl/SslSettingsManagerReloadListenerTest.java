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

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

import com.carrotsearch.randomizedtesting.RandomizedTest;
import org.awaitility.Awaitility;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.bouncycastle.cert.X509CertificateHolder;

import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.env.TestEnvironment;
import org.opensearch.security.ssl.config.CertType;
import org.opensearch.threadpool.TestThreadPool;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import static org.opensearch.security.ssl.CertificatesUtils.privateKeyToPemObject;
import static org.opensearch.security.ssl.CertificatesUtils.writePemContent;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.KEYSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.KEYSTORE_TYPE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_CERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_KEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_TRUSTED_CAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_AUX_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.TRUSTSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.TRUSTSTORE_TYPE;
import static org.opensearch.transport.AuxTransport.AUX_TRANSPORT_TYPES_SETTING;

public class SslSettingsManagerReloadListenerTest extends RandomizedTest {

    @ClassRule
    public static CertificatesRule certificatesRule = new CertificatesRule(false);

    ThreadPool threadPool;

    ResourceWatcherService resourceWatcherService;

    private static final String MOCK_AUX_PREFIX_FOO = SSL_AUX_PREFIX + "foo.";
    private static final CertType MOCK_AUX_CERT_TYPE_FOO = new CertType(MOCK_AUX_PREFIX_FOO);

    @FunctionalInterface
    interface CertificatesWriter {
        void write(
            final String filePrefix,
            final X509CertificateHolder caCertificate,
            final Tuple<PrivateKey, X509CertificateHolder> accessKeyAndCertificate
        ) throws Exception;
    }

    @Before
    public void setUp() throws Exception {
        threadPool = new TestThreadPool("reload tests");
        resourceWatcherService = new ResourceWatcherService(
            Settings.builder().put("resource.reload.interval.high", "1s").build(),
            threadPool
        );
    }

    static Path path(final String fileName) {
        return certificatesRule.configRootFolder().resolve(fileName);
    }

    @After
    public void cleanUp() {
        if (resourceWatcherService != null) {
            resourceWatcherService.close();
        }
        if (threadPool != null) {
            ThreadPool.terminate(threadPool, 10, TimeUnit.SECONDS);
        }
    }

    @Test
    public void testReloadsSslContextOnPemStoreFilesChangedForHttp() throws Exception {
        reloadSslContextOnPemFilesChangedForTransportType(CertType.HTTP, defaultSettingsBuilder());
    }

    @Test
    public void testReloadsSslContextOnPemStoreFilesChangedForAux() throws Exception {
        Settings.Builder settings = defaultSettingsBuilder().putList(
            AUX_TRANSPORT_TYPES_SETTING.getKey(),
            List.of(MOCK_AUX_CERT_TYPE_FOO.id())
        ).put(MOCK_AUX_CERT_TYPE_FOO.sslSettingPrefix() + ENABLED, true);
        reloadSslContextOnPemFilesChangedForTransportType(MOCK_AUX_CERT_TYPE_FOO, settings);
    }

    @Test
    public void testReloadsSslContextOnPemStoreFilesChangedForTransport() throws Exception {
        reloadSslContextOnPemFilesChangedForTransportType(CertType.TRANSPORT, defaultSettingsBuilder());
    }

    @Test
    public void testReloadsSslContextOnJdkStoreFilesChangedForHttp() throws Exception {
        reloadSslContextOnJdkStoreFilesChangedForTransportType(CertType.HTTP, defaultSettingsBuilder());
    }

    @Test
    public void testReloadsSslContextOnJdkStoreFilesChangedForAux() throws Exception {
        Settings.Builder settings = defaultSettingsBuilder().putList(
            AUX_TRANSPORT_TYPES_SETTING.getKey(),
            List.of(MOCK_AUX_CERT_TYPE_FOO.id())
        ).put(MOCK_AUX_CERT_TYPE_FOO.sslSettingPrefix() + ENABLED, true);
        reloadSslContextOnJdkStoreFilesChangedForTransportType(MOCK_AUX_CERT_TYPE_FOO, settings);
    }

    @Test
    public void testReloadsSslContextOnJdkStoreFilesChangedForTransport() throws Exception {
        reloadSslContextOnJdkStoreFilesChangedForTransportType(CertType.TRANSPORT, defaultSettingsBuilder());
    }

    private void reloadSslContextOnJdkStoreFilesChangedForTransportType(CertType certType, Settings.Builder settings) throws Exception {
        final String settingPrefix = certType.sslSettingPrefix();
        final String enabledSetting = settingPrefix + ENABLED;
        final String trustStorePathSetting = settingPrefix + TRUSTSTORE_FILEPATH;
        final String trustStoreTypeSetting = settingPrefix + TRUSTSTORE_TYPE;
        final String keyStorePathSetting = settingPrefix + KEYSTORE_FILEPATH;
        final String keyStoreTypeSetting = settingPrefix + KEYSTORE_TYPE;
        final String certTypeFilePrefix = certType.id().toLowerCase(Locale.ROOT);
        final var keyStorePassword = randomAsciiAlphanumOfLength(10);
        final var secureSettings = new MockSecureSettings();
        secureSettings.setString(settingPrefix + "truststore_password_secure", keyStorePassword);
        secureSettings.setString(settingPrefix + "keystore_password_secure", keyStorePassword);
        secureSettings.setString(settingPrefix + "keystore_keypassword_secure", certificatesRule.privateKeyPassword());
        reloadSslContextOnFilesChanged(
            certType,
            settings
                // Disable transport layer to test server transports independently.
                // If certType is TRANSPORT the following line will re-enable it.
                .put(SECURITY_SSL_TRANSPORT_ENABLED, false)
                .put(enabledSetting, true)
                .put(trustStorePathSetting, path(certTypeFilePrefix + "_truststore.jks"))
                .put(trustStoreTypeSetting, "jks")
                .put(keyStorePathSetting, path(certTypeFilePrefix + "_keystore.p12"))
                .put(keyStoreTypeSetting, "pkcs12")
                .setSecureSettings(secureSettings)
                .build(),
            (filePrefix, caCertificate, accessKeyAndCertificate) -> {
                final var trustStore = KeyStore.getInstance("jks");
                trustStore.load(null, null);
                trustStore.setCertificateEntry("ca", certificatesRule.toX509Certificate(caCertificate));
                writeStore(trustStore, path(String.format("%s_truststore.jks", filePrefix)), keyStorePassword);
                final var keyStore = KeyStore.getInstance("pkcs12");
                keyStore.load(null, null);
                keyStore.setKeyEntry(
                    "pk",
                    accessKeyAndCertificate.v1(),
                    certificatesRule.privateKeyPassword().toCharArray(),
                    new X509Certificate[] { certificatesRule.toX509Certificate(accessKeyAndCertificate.v2()) }
                );
                writeStore(keyStore, path(String.format("%s_keystore.p12", filePrefix)), keyStorePassword);
            }
        );
    }

    private void reloadSslContextOnPemFilesChangedForTransportType(CertType certType, Settings.Builder settings) throws Exception {
        final String settingPrefix = certType.sslSettingPrefix();
        final String enabledSetting = settingPrefix + ENABLED;
        final String pemTrustCasPathSetting = settingPrefix + PEM_TRUSTED_CAS_FILEPATH;
        final String pemCertPathSetting = settingPrefix + PEM_CERT_FILEPATH;
        final String pemKeyPathSetting = settingPrefix + PEM_KEY_FILEPATH;
        final String certTypeFilePrefix = certType.id().toLowerCase(Locale.ROOT);
        MockSecureSettings secureSettings = new MockSecureSettings();
        secureSettings.setString(settingPrefix + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        reloadSslContextOnFilesChanged(
            certType,
            settings
                // Disable transport layer to test server transports independently.
                // If certType is TRANSPORT the following line will re-enable it.
                .put(SECURITY_SSL_TRANSPORT_ENABLED, false)
                .put(enabledSetting, true)
                .put(pemTrustCasPathSetting, path(certTypeFilePrefix + "_ca_certificate.pem"))
                .put(pemCertPathSetting, path(certTypeFilePrefix + "_access_certificate.pem"))
                .put(pemKeyPathSetting, path(certTypeFilePrefix + "_access_certificate_pk.pem"))
                .setSecureSettings(secureSettings)
                .build(),
            (filePrefix, caCertificate, accessKeyAndCertificate) -> {
                writePemContent(path(String.format("%s_ca_certificate.pem", filePrefix)), caCertificate);
                writePemContent(path(String.format("%s_access_certificate.pem", filePrefix)), accessKeyAndCertificate.v2());
                writePemContent(
                    path(String.format("%s_access_certificate_pk.pem", filePrefix)),
                    privateKeyToPemObject(accessKeyAndCertificate.v1(), certificatesRule.privateKeyPassword())
                );
            }
        );
    }

    private void reloadSslContextOnFilesChanged(CertType certType, final Settings settings, final CertificatesWriter certificatesWriter)
        throws Exception {
        final String certNamePrefix = certType.id().toLowerCase(Locale.ROOT);
        final var defaultCertificates = generateCertificates();
        var defaultKeyPair = defaultCertificates.v1();
        var caCertificate = defaultCertificates.v2().v1();
        var accessKeyAndCertificate = defaultCertificates.v2().v2();
        certificatesWriter.write(certNamePrefix, caCertificate, accessKeyAndCertificate);
        final var sslSettingsManager = new SslSettingsManager(TestEnvironment.newEnvironment(settings));
        sslSettingsManager.addSslConfigurationsChangeListener(resourceWatcherService);
        final var sslContextBefore = sslSettingsManager.sslContextHandler(certType).orElseThrow().sslContext();
        if (randomBoolean()) {
            caCertificate = certificatesRule.generateCaCertificate(
                defaultKeyPair,
                caCertificate.getNotBefore().toInstant(),
                caCertificate.getNotAfter().toInstant().plus(365, ChronoUnit.DAYS)
            );
        } else {
            accessKeyAndCertificate = certificatesRule.generateAccessCertificate(
                defaultKeyPair,
                accessKeyAndCertificate.v2().getNotBefore().toInstant(),
                accessKeyAndCertificate.v2().getNotAfter().toInstant().plus(365, ChronoUnit.DAYS)
            );
        }
        certificatesWriter.write(certNamePrefix, caCertificate, accessKeyAndCertificate);
        Awaitility.await("Wait for reloading SSL context").until(() -> {
            final var sslContextAfter = sslSettingsManager.sslContextHandler(certType).orElseThrow().sslContext();
            return !sslContextAfter.equals(sslContextBefore);
        });
    }

    private Tuple<KeyPair, Tuple<X509CertificateHolder, Tuple<PrivateKey, X509CertificateHolder>>> generateCertificates() throws Exception {
        final var defaultKeyPair = certificatesRule.generateKeyPair();
        return Tuple.tuple(
            defaultKeyPair,
            Tuple.tuple(certificatesRule.generateCaCertificate(defaultKeyPair), certificatesRule.generateAccessCertificate(defaultKeyPair))
        );
    }

    Settings.Builder defaultSettingsBuilder() {
        return Settings.builder()
            .put(Environment.PATH_HOME_SETTING.getKey(), certificatesRule.configRootFolder().toString())
            .put("client.type", "node");
    }

    void writeStore(final KeyStore keyStore, final Path path, final String password) throws Exception {
        try (final var out = Files.newOutputStream(path)) {
            keyStore.store(out, password.toCharArray());
        }
    }

}
