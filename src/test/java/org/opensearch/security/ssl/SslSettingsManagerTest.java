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

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

import com.carrotsearch.randomizedtesting.RandomizedTest;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.env.TestEnvironment;
import org.opensearch.security.ssl.config.CertType;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.ssl.CertificatesUtils.privateKeyToPemObject;
import static org.opensearch.security.ssl.CertificatesUtils.writePemContent;
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
import static org.opensearch.security.support.ConfigConstants.SECURITY_SSL_ONLY;
import static org.junit.Assert.assertThrows;

public class SslSettingsManagerTest extends RandomizedTest {

    @ClassRule
    public static CertificatesRule certificatesRule = new CertificatesRule();

    @BeforeClass
    public static void setUp() throws Exception {
        writeCertificates("ca_http_certificate.pem", "access_http_certificate.pem", "access_http_certificate_pk.pem");
        writeCertificates("ca_transport_certificate.pem", "access_transport_certificate.pem", "access_transport_certificate_pk.pem");
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
    public void failsIfNoSslSet() throws Exception {
        final var settings = defaultSettingsBuilder().build();
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(settings)));
    }

    @Test
    public void transportFailsIfNoConfigDefine() throws Exception {
        final var noTransportSettings = defaultSettingsBuilder().put(SECURITY_SSL_HTTP_ENABLED, true).build();
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(noTransportSettings)));
    }

    @Test
    public void transportFailsIfConfigEnabledButNotDefined() throws Exception {
        final var noTransportSettingsButItEnabled = defaultSettingsBuilder().put(SECURITY_SSL_TRANSPORT_ENABLED, true).build();
        assertThrows(
            OpenSearchException.class,
            () -> new SslSettingsManager(TestEnvironment.newEnvironment(noTransportSettingsButItEnabled))
        );
    }

    @Test
    public void transportFailsIfJdkTrustStoreHasNotBeenSet() throws Exception {
        final var noTransportSettingsButItEnabled = defaultSettingsBuilder().put(SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, certificatesRule.configRootFolder().toString())
            .build();
        assertThrows(
            OpenSearchException.class,
            () -> new SslSettingsManager(TestEnvironment.newEnvironment(noTransportSettingsButItEnabled))
        );
    }

    @Test
    public void transportFailsIfExtendedKeyUsageEnabledForJdkKeyStoreButNotConfigured() throws Exception {
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
    public void transportFailsIfExtendedKeyUsageEnabledForPemKeyStoreButNotConfigured() throws Exception {
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
    public void transportFailsIfConfigDisabled() throws Exception {
        Settings settings = defaultSettingsBuilder().put(SECURITY_SSL_HTTP_ENABLED, true)
            .put(SECURITY_SSL_TRANSPORT_ENABLED, false)
            .build();
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(settings)));
    }

    @Test
    public void httpConfigFailsIfBothPemAndJDKSettingsWereSet() throws Exception {
        final var keyStoreSettings = randomFrom(List.of(SECURITY_SSL_HTTP_KEYSTORE_FILEPATH));
        final var pemKeyStoreSettings = randomFrom(
            List.of(SECURITY_SSL_HTTP_PEMKEY_FILEPATH, SECURITY_SSL_HTTP_PEMCERT_FILEPATH, SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH)
        );
        final var settings = defaultSettingsBuilder().put(SECURITY_SSL_HTTP_ENABLED, true)
            .put(keyStoreSettings, "aaa")
            .put(pemKeyStoreSettings, "bbb")
            .build();
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(settings)));
    }

    @Test
    public void httpConfigFailsIfHttpEnabledButButNotDefined() throws Exception {
        final var settings = defaultSettingsBuilder().put(SECURITY_SSL_HTTP_ENABLED, true).build();
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(settings)));
    }

    @Test
    public void httpConfigFailsIfClientAuthRequiredAndJdkTrustStoreNotSet() throws Exception {
        final var settings = defaultSettingsBuilder().put(SECURITY_SSL_HTTP_ENABLED, true)
            .put(SECURITY_SSL_HTTP_CLIENTAUTH_MODE, ClientAuth.REQUIRE.name().toLowerCase(Locale.ROOT))
            .put(SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, certificatesRule.configRootFolder().toString())
            .build();
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(settings)));
    }

    @Test
    public void httpConfigFailsIfClientAuthRequiredAndPemTrustedCasNotSet() throws Exception {
        final var settings = defaultSettingsBuilder().put(SECURITY_SSL_HTTP_ENABLED, true)
            .put(SECURITY_SSL_HTTP_CLIENTAUTH_MODE, ClientAuth.REQUIRE.name().toLowerCase(Locale.ROOT))
            .put(SECURITY_SSL_HTTP_PEMKEY_FILEPATH, "aaa")
            .put(SECURITY_SSL_HTTP_PEMCERT_FILEPATH, "bbb")
            .build();
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(settings)));
    }

    @Test
    public void loadConfigurationAndBuildHSslContextForSslOnlyMode() throws Exception {
        final var securitySettings = new MockSecureSettings();
        securitySettings.setString(SSL_TRANSPORT_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(SSL_HTTP_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        final var settingsBuilder = defaultSettingsBuilder().setSecureSettings(securitySettings);
        withTransportSslSettings(
            settingsBuilder,
            "ca_transport_certificate.pem",
            "access_transport_certificate.pem",
            "access_transport_certificate_pk.pem"
        );
        withHttpSslSettings(settingsBuilder);
        final var transportEnabled = randomBoolean();
        final var sslSettingsManager = new SslSettingsManager(
            TestEnvironment.newEnvironment(
                settingsBuilder.put(SECURITY_SSL_TRANSPORT_ENABLED, transportEnabled).put(SECURITY_SSL_ONLY, true).build()
            )
        );

        assertThat("Loaded HTTP configuration", sslSettingsManager.sslConfiguration(CertType.HTTP).isPresent());
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
    }

    @Test
    public void loadConfigurationAndBuildSslContextForClientNode() throws Exception {
        final var securitySettings = new MockSecureSettings();
        securitySettings.setString(SSL_TRANSPORT_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(SSL_HTTP_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        final var settingsBuilder = defaultSettingsBuilder().setSecureSettings(securitySettings);
        withTransportSslSettings(
            settingsBuilder,
            "ca_transport_certificate.pem",
            "access_transport_certificate.pem",
            "access_transport_certificate_pk.pem"
        );
        withHttpSslSettings(settingsBuilder);
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
    public void loadConfigurationAndBuildSslContexts() throws Exception {
        final var securitySettings = new MockSecureSettings();
        securitySettings.setString(SSL_TRANSPORT_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(SSL_HTTP_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        final var settingsBuilder = defaultSettingsBuilder().setSecureSettings(securitySettings);
        withTransportSslSettings(
            settingsBuilder,
            "ca_transport_certificate.pem",
            "access_transport_certificate.pem",
            "access_transport_certificate_pk.pem"
        );
        withHttpSslSettings(settingsBuilder);
        final var sslSettingsManager = new SslSettingsManager(TestEnvironment.newEnvironment(settingsBuilder.build()));
        assertThat("Loaded HTTP configuration", sslSettingsManager.sslConfiguration(CertType.HTTP).isPresent());
        assertThat("Loaded Transport configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT).isPresent());
        assertThat("Loaded Transport Client configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT).isPresent());

        assertThat("Built HTTP SSL Context", sslSettingsManager.sslContextHandler(CertType.HTTP).isPresent());
        assertThat("Built Transport SSL Context", sslSettingsManager.sslContextHandler(CertType.TRANSPORT).isPresent());
        assertThat("Built Transport Client SSL Context", sslSettingsManager.sslContextHandler(CertType.TRANSPORT_CLIENT).isPresent());

        assertThat(
            "Built Server SSL context for HTTP",
            sslSettingsManager.sslContextHandler(CertType.HTTP).map(SslContextHandler::sslContext).map(SslContext::isServer).orElse(false)
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
    public void loadConfigurationAndBuildTransportSslContext() throws Exception {
        final var securitySettings = new MockSecureSettings();
        securitySettings.setString(SSL_TRANSPORT_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        final var settingsBuilder = defaultSettingsBuilder().setSecureSettings(securitySettings);
        withTransportSslSettings(
            settingsBuilder,
            "ca_transport_certificate.pem",
            "access_transport_certificate.pem",
            "access_transport_certificate_pk.pem"
        );
        final var sslSettingsManager = new SslSettingsManager(TestEnvironment.newEnvironment(settingsBuilder.build()));

        assertThat("Didn't load HTTP configuration", sslSettingsManager.sslConfiguration(CertType.HTTP).isEmpty());
        assertThat("Loaded Transport configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT).isPresent());
        assertThat("Loaded Transport Client configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT).isPresent());
        assertThat(
            "SSL configuration for Transport and Transport Client is the same",
            sslSettingsManager.sslConfiguration(CertType.TRANSPORT)
                .flatMap(t -> sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT).map(tc -> tc.equals(t)))
                .orElse(false)
        );

        assertThat("Built HTTP SSL Context", sslSettingsManager.sslContextHandler(CertType.HTTP).isEmpty());
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
        assertThat("Loaded Transport configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT).isPresent());
        assertThat("Loaded Transport Client configuration", sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT).isPresent());
        assertThat(
            "SSL configuration for Transport and Transport Client is not the same",
            sslSettingsManager.sslConfiguration(CertType.TRANSPORT)
                .flatMap(t -> sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT).map(tc -> !tc.equals(t)))
                .orElse(true)
        );
        assertThat("Built HTTP SSL Context", sslSettingsManager.sslContextHandler(CertType.HTTP).isEmpty());
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

    private void withTransportSslSettings(
        final Settings.Builder settingsBuilder,
        final String caFileName,
        final String accessFileName,
        final String accessPkFileName
    ) {
        settingsBuilder.put(SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, path(caFileName))
            .put(SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, path(accessFileName))
            .put(SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, path(accessPkFileName));
    }

    private void withHttpSslSettings(final Settings.Builder settingsBuilder) {
        settingsBuilder.put(SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(SECURITY_SSL_HTTP_ENABLED, true)
            .put(SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, path("ca_http_certificate.pem"))
            .put(SECURITY_SSL_HTTP_PEMCERT_FILEPATH, path("access_http_certificate.pem"))
            .put(SECURITY_SSL_HTTP_PEMKEY_FILEPATH, path("access_http_certificate_pk.pem"));
    }

    Settings.Builder defaultSettingsBuilder() {
        return Settings.builder()
            .put(Environment.PATH_HOME_SETTING.getKey(), certificatesRule.configRootFolder().toString())
            .put("client.type", "node");
    }

}
