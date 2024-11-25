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
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_TYPE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_TYPE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_HTTP_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_PREFIX;

public class SslSettingsManagerReloadListenerTest extends RandomizedTest {

    @ClassRule
    public static CertificatesRule certificatesRule = new CertificatesRule(false);

    ThreadPool threadPool;

    ResourceWatcherService resourceWatcherService;

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
    public void reloadsSslContextOnPemFilesChanged() throws Exception {
        final var securitySettings = new MockSecureSettings();
        securitySettings.setString(SSL_HTTP_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(SSL_TRANSPORT_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        reloadSslContextOnFilesChanged(
            defaultSettingsBuilder().put(SECURITY_SSL_HTTP_ENABLED, true)
                .put(SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, path("http_ca_certificate.pem"))
                .put(SECURITY_SSL_HTTP_PEMCERT_FILEPATH, path("http_access_certificate.pem"))
                .put(SECURITY_SSL_HTTP_PEMKEY_FILEPATH, path("http_access_certificate_pk.pem"))
                .put(SECURITY_SSL_TRANSPORT_ENABLED, true)
                .put(SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, path("transport_ca_certificate.pem"))
                .put(SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, path("transport_access_certificate.pem"))
                .put(SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, path("transport_access_certificate_pk.pem"))
                .setSecureSettings(securitySettings)
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

    @Test
    public void reloadsSslContextOnJdkStoreFilesChanged() throws Exception {
        final var keyStorePassword = randomAsciiAlphanumOfLength(10);
        final var secureSettings = new MockSecureSettings();
        secureSettings.setString(SSL_HTTP_PREFIX + "truststore_password_secure", keyStorePassword);
        secureSettings.setString(SSL_HTTP_PREFIX + "keystore_password_secure", keyStorePassword);
        secureSettings.setString(SSL_HTTP_PREFIX + "keystore_keypassword_secure", certificatesRule.privateKeyPassword());

        secureSettings.setString(SSL_TRANSPORT_PREFIX + "truststore_password_secure", keyStorePassword);
        secureSettings.setString(SSL_TRANSPORT_PREFIX + "keystore_password_secure", keyStorePassword);
        secureSettings.setString(SSL_TRANSPORT_PREFIX + "keystore_keypassword_secure", certificatesRule.privateKeyPassword());
        reloadSslContextOnFilesChanged(
            defaultSettingsBuilder().put(SECURITY_SSL_HTTP_ENABLED, true)
                .put(SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH, path("http_truststore.jks"))
                .put(SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, "jks")
                .put(SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, path("http_keystore.p12"))
                .put(SECURITY_SSL_HTTP_KEYSTORE_TYPE, "pkcs12")
                .put(SECURITY_SSL_TRANSPORT_ENABLED, true)
                .put(SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, path("transport_truststore.jks"))
                .put(SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE, "jks")
                .put(SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, path("transport_keystore.p12"))
                .put(SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, "pkcs12")
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

    void reloadSslContextOnFilesChanged(final Settings settings, final CertificatesWriter certificatesWriter) throws Exception {
        final var defaultHttpCertificates = generateCertificates();
        final var defaultHttpKeyPair = defaultHttpCertificates.v1();
        final var httpCaCertificate = defaultHttpCertificates.v2().v1();
        final var httpAccessKeyAndCertificate = defaultHttpCertificates.v2().v2();

        final var defaultTransportCertificates = generateCertificates();
        final var defaultTransportKeyPair = defaultTransportCertificates.v1();
        final var transportCaCertificate = defaultTransportCertificates.v2().v1();
        final var transportAccessKeyAndCertificate = defaultTransportCertificates.v2().v2();

        final var reloadHttpCertificates = randomBoolean();

        certificatesWriter.write("http", httpCaCertificate, httpAccessKeyAndCertificate);
        certificatesWriter.write("transport", transportCaCertificate, transportAccessKeyAndCertificate);

        final var sslSettingsManager = new SslSettingsManager(TestEnvironment.newEnvironment(settings));
        sslSettingsManager.addSslConfigurationsChangeListener(resourceWatcherService);

        final var httpSslContextBefore = sslSettingsManager.sslContextHandler(CertType.HTTP).orElseThrow().sslContext();
        final var transportSslContextBefore = sslSettingsManager.sslContextHandler(CertType.TRANSPORT).orElseThrow().sslContext();
        final var transportClientSslContextBefore = sslSettingsManager.sslContextHandler(CertType.TRANSPORT_CLIENT)
            .orElseThrow()
            .sslContext();

        final var filePrefix = reloadHttpCertificates ? "http" : "transport";
        final var keyPair = reloadHttpCertificates ? defaultHttpKeyPair : defaultTransportKeyPair;
        var caCertificate = reloadHttpCertificates ? httpCaCertificate : transportCaCertificate;
        var keyAndCertificate = reloadHttpCertificates ? httpAccessKeyAndCertificate : transportAccessKeyAndCertificate;

        if (randomBoolean()) {
            caCertificate = certificatesRule.generateCaCertificate(
                keyPair,
                caCertificate.getNotBefore().toInstant(),
                caCertificate.getNotAfter().toInstant().plus(365, ChronoUnit.DAYS)
            );
        } else {
            keyAndCertificate = certificatesRule.generateAccessCertificate(
                keyPair,
                keyAndCertificate.v2().getNotBefore().toInstant(),
                keyAndCertificate.v2().getNotAfter().toInstant().plus(365, ChronoUnit.DAYS)
            );
        }
        certificatesWriter.write(filePrefix, caCertificate, keyAndCertificate);
        Awaitility.await("Wait for reloading SSL context").until(() -> {
            final var httpSslContextAfter = sslSettingsManager.sslContextHandler(CertType.HTTP).orElseThrow().sslContext();
            final var transportSslContextAfter = sslSettingsManager.sslContextHandler(CertType.TRANSPORT).orElseThrow().sslContext();
            final var transportClientSslContextAfter = sslSettingsManager.sslContextHandler(CertType.TRANSPORT_CLIENT)
                .orElseThrow()
                .sslContext();

            if (reloadHttpCertificates) {
                return !httpSslContextAfter.equals(httpSslContextBefore)
                    && transportSslContextBefore.equals(transportSslContextAfter)
                    && transportClientSslContextBefore.equals(transportClientSslContextAfter);
            } else {
                return httpSslContextAfter.equals(httpSslContextBefore)
                    && !transportSslContextBefore.equals(transportSslContextAfter)
                    && !transportClientSslContextBefore.equals(transportClientSslContextAfter);
            }
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
