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
import static org.opensearch.plugins.NetworkPlugin.AuxTransport.AUX_TRANSPORT_TYPES_SETTING;
import static org.opensearch.security.ssl.CertificatesUtils.privateKeyToPemObject;
import static org.opensearch.security.ssl.CertificatesUtils.writePemContent;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_CLIENTAUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_ENABLED;
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
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_AUX_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_HTTP_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_SERVER_EXTENDED_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.getBoolAffixKeyForCertType;
import static org.opensearch.security.ssl.util.SSLConfigConstants.getStringAffixKeyForCertType;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SSL_ONLY;
import static org.junit.Assert.assertThrows;

public class SslSettingsManagerTest extends RandomizedTest {

    @ClassRule
    public static CertificatesRule certificatesRule = new CertificatesRule();

    /*
    Settings for a mock aux transport - foo
     */
    private static final String MOCK_AUX_PREFIX_FOO = SSL_AUX_PREFIX + "foo.";
    private static final CertType MOCK_AUX_CERT_TYPE_FOO = new CertType(MOCK_AUX_PREFIX_FOO);
    private static final Settings ENABLE_FOO_SETTINGS_BUILDER = Settings.builder()
            .putList(AUX_TRANSPORT_TYPES_SETTING.getKey(), List.of(MOCK_AUX_CERT_TYPE_FOO.name()))
            .put(getBoolAffixKeyForCertType(SECURITY_SSL_AUX_ENABLED, MOCK_AUX_CERT_TYPE_FOO), true)
            .build();
    private static final String MOCK_AUX_CERT_TYPE_FOO_PEMTRUSTEDCAS_FILEPATH = getStringAffixKeyForCertType(SECURITY_SSL_AUX_PEMTRUSTEDCAS_FILEPATH, MOCK_AUX_CERT_TYPE_FOO);
    private static final String MOCK_AUX_CERT_TYPE_FOO_PEMCERT_FILEPATH = getStringAffixKeyForCertType(SECURITY_SSL_AUX_PEMCERT_FILEPATH, MOCK_AUX_CERT_TYPE_FOO);
    private static final String MOCK_AUX_CERT_TYPE_FOO_PEMKEY_FILEPATH = getStringAffixKeyForCertType(SECURITY_SSL_AUX_PEMKEY_FILEPATH, MOCK_AUX_CERT_TYPE_FOO);
    private static final String MOCK_AUX_CERT_TYPE_FOO_PEMTRUSTEDCAS_NAME = "ca_" + MOCK_AUX_CERT_TYPE_FOO.name() + "_certificate.pem";
    private static final String MOCK_AUX_CERT_TYPE_FOO_PEMCERT_NAME = "access_" + MOCK_AUX_CERT_TYPE_FOO.name() + "_certificate.pem";
    private static final String MOCK_AUX_CERT_TYPE_FOO_PEMKEY_NAME = "access_" + MOCK_AUX_CERT_TYPE_FOO.name() + "_certificate_pk.pem";

    /*
    Settings for a mock aux transport - bar
     */
    private static final String MOCK_AUX_PREFIX_BAR = SSL_AUX_PREFIX + "bar.";
    private static final CertType MOCK_AUX_CERT_TYPE_BAR = new CertType(MOCK_AUX_PREFIX_BAR);
    private static final Settings ENABLE_BAR_SETTINGS_BUILDER = Settings.builder()
            .putList(AUX_TRANSPORT_TYPES_SETTING.getKey(), List.of(MOCK_AUX_CERT_TYPE_BAR.name()))
            .put(getBoolAffixKeyForCertType(SECURITY_SSL_AUX_ENABLED, MOCK_AUX_CERT_TYPE_BAR), true)
            .build();
    private static final String MOCK_AUX_CERT_TYPE_BAR_PEMTRUSTEDCAS_FILEPATH = getStringAffixKeyForCertType(SECURITY_SSL_AUX_PEMTRUSTEDCAS_FILEPATH, MOCK_AUX_CERT_TYPE_BAR);
    private static final String MOCK_AUX_CERT_TYPE_BAR_PEMCERT_FILEPATH = getStringAffixKeyForCertType(SECURITY_SSL_AUX_PEMCERT_FILEPATH, MOCK_AUX_CERT_TYPE_BAR);
    private static final String MOCK_AUX_CERT_TYPE_BAR_PEMKEY_FILEPATH = getStringAffixKeyForCertType(SECURITY_SSL_AUX_PEMKEY_FILEPATH, MOCK_AUX_CERT_TYPE_BAR);
    private static final String MOCK_AUX_CERT_TYPE_BAR_PEMTRUSTEDCAS_NAME = "ca_" + MOCK_AUX_CERT_TYPE_BAR.name() + "_certificate.pem";
    private static final String MOCK_AUX_CERT_TYPE_BAR_PEMCERT_NAME = "access_" + MOCK_AUX_CERT_TYPE_BAR.name() + "_certificate.pem";
    private static final String MOCK_AUX_CERT_TYPE_BAR_PEMKEY_NAME = "access_" + MOCK_AUX_CERT_TYPE_BAR.name() + "_certificate_pk.pem";

    static Settings.Builder defaultSettingsBuilder() {
        return Settings.builder()
                .put(Environment.PATH_HOME_SETTING.getKey(), certificatesRule.configRootFolder().toString())
                .put("client.type", "node");
    }

    private void withTransportSslSettings(final Settings.Builder settingsBuilder) {
        settingsBuilder.put(SECURITY_SSL_TRANSPORT_ENABLED, true)
                .put(SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, path("ca_transport_certificate.pem"))
                .put(SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, path("access_transport_certificate.pem"))
                .put(SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, path("access_transport_certificate_pk.pem"));
    }

    private void withHttpSslSettings(final Settings.Builder settingsBuilder) {
        settingsBuilder.put(SECURITY_SSL_TRANSPORT_ENABLED, true)
                .put(SECURITY_SSL_HTTP_ENABLED, true)
                .put(SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, path("ca_http_certificate.pem"))
                .put(SECURITY_SSL_HTTP_PEMCERT_FILEPATH, path("access_http_certificate.pem"))
                .put(SECURITY_SSL_HTTP_PEMKEY_FILEPATH, path("access_http_certificate_pk.pem"));
    }

    private void withAuxFooSslSettings(final Settings.Builder settingsBuilder) {
        settingsBuilder.put(ENABLE_FOO_SETTINGS_BUILDER)
                .put(MOCK_AUX_CERT_TYPE_FOO_PEMTRUSTEDCAS_FILEPATH, path(MOCK_AUX_CERT_TYPE_FOO_PEMTRUSTEDCAS_NAME))
                .put(MOCK_AUX_CERT_TYPE_FOO_PEMCERT_FILEPATH, path(MOCK_AUX_CERT_TYPE_FOO_PEMCERT_NAME))
                .put(MOCK_AUX_CERT_TYPE_FOO_PEMKEY_FILEPATH, path(MOCK_AUX_CERT_TYPE_FOO_PEMKEY_NAME));
    }

    private void withAuxBarSslSettings(final Settings.Builder settingsBuilder) {
        settingsBuilder.put(ENABLE_BAR_SETTINGS_BUILDER)
                .put(MOCK_AUX_CERT_TYPE_BAR_PEMTRUSTEDCAS_FILEPATH, path(MOCK_AUX_CERT_TYPE_BAR_PEMTRUSTEDCAS_NAME))
                .put(MOCK_AUX_CERT_TYPE_BAR_PEMCERT_FILEPATH, path(MOCK_AUX_CERT_TYPE_BAR_PEMCERT_NAME))
                .put(MOCK_AUX_CERT_TYPE_BAR_PEMKEY_FILEPATH, path(MOCK_AUX_CERT_TYPE_BAR_PEMKEY_NAME));
    }

    @BeforeClass
    public static void setUp() throws Exception {
        writeCertificates("ca_http_certificate.pem", "access_http_certificate.pem", "access_http_certificate_pk.pem");
        writeCertificates("ca_transport_certificate.pem", "access_transport_certificate.pem", "access_transport_certificate_pk.pem");
        writeCertificates("ca_" + MOCK_AUX_CERT_TYPE_FOO.name() + "_certificate.pem",
                "access_" + MOCK_AUX_CERT_TYPE_FOO.name() + "_certificate.pem",
                "access_" + MOCK_AUX_CERT_TYPE_FOO.name() + "_certificate_pk.pem");
        writeCertificates("ca_" + MOCK_AUX_CERT_TYPE_BAR.name() + "_certificate.pem",
                "access_" + MOCK_AUX_CERT_TYPE_BAR.name() + "_certificate.pem",
                "access_" + MOCK_AUX_CERT_TYPE_BAR.name() + "_certificate_pk.pem");
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
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(defaultSettingsBuilder().put(SECURITY_SSL_HTTP_ENABLED, true).build())));
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(defaultSettingsBuilder().put(SECURITY_SSL_TRANSPORT_ENABLED, true).build())));
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(defaultSettingsBuilder().put(ENABLE_FOO_SETTINGS_BUILDER).build())));
        assertThrows(OpenSearchException.class, () -> new SslSettingsManager(TestEnvironment.newEnvironment(defaultSettingsBuilder().put(ENABLE_BAR_SETTINGS_BUILDER).build())));
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
            List.of(getStringAffixKeyForCertType(SECURITY_SSL_AUX_PEMKEY_FILEPATH, MOCK_AUX_CERT_TYPE_FOO),
                getStringAffixKeyForCertType(SECURITY_SSL_AUX_PEMCERT_FILEPATH, MOCK_AUX_CERT_TYPE_FOO),
                getStringAffixKeyForCertType(SECURITY_SSL_AUX_PEMTRUSTEDCAS_FILEPATH, MOCK_AUX_CERT_TYPE_FOO))
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
        securitySettings.setString(MOCK_AUX_CERT_TYPE_FOO.sslSettingPrefix() + "pemkey_password_secure", certificatesRule.privateKeyPassword());

        final var settingsBuilder = defaultSettingsBuilder().setSecureSettings(securitySettings);
        withTransportSslSettings(settingsBuilder);
        withHttpSslSettings(settingsBuilder);
        withAuxFooSslSettings(settingsBuilder);

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
            sslSettingsManager.sslContextHandler(MOCK_AUX_CERT_TYPE_FOO).map(SslContextHandler::sslContext).map(SslContext::isServer).orElse(false)
        );
    }

    @Test
    public void loadConfigurationAndBuildSslContextForClientNode() {
        final var securitySettings = new MockSecureSettings();
        securitySettings.setString(SSL_TRANSPORT_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(SSL_HTTP_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());

        final var settingsBuilder = defaultSettingsBuilder().setSecureSettings(securitySettings);
        withTransportSslSettings(settingsBuilder);
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
    public void loadConfigurationAndBuildSslContextsMultipleAuxTransports() {
        final var securitySettings = new MockSecureSettings();
        securitySettings.setString(SSL_TRANSPORT_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(SSL_HTTP_PREFIX + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(MOCK_AUX_CERT_TYPE_FOO.sslSettingPrefix() + "pemkey_password_secure", certificatesRule.privateKeyPassword());
        securitySettings.setString(MOCK_AUX_CERT_TYPE_BAR.sslSettingPrefix() + "pemkey_password_secure", certificatesRule.privateKeyPassword());

        final var settingsBuilder = defaultSettingsBuilder().setSecureSettings(securitySettings);
        withTransportSslSettings(settingsBuilder);
        withHttpSslSettings(settingsBuilder);
        withAuxBarSslSettings(settingsBuilder);
        withAuxFooSslSettings(settingsBuilder);
        settingsBuilder.put(Settings.builder()
                .putList(AUX_TRANSPORT_TYPES_SETTING.getKey(), List.of(MOCK_AUX_CERT_TYPE_BAR.name(), MOCK_AUX_CERT_TYPE_FOO.name()))
                .build());

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
                sslSettingsManager.sslContextHandler(MOCK_AUX_CERT_TYPE_FOO).map(SslContextHandler::sslContext).map(SslContext::isServer).orElse(false)
        );
        assertThat(
                "Built Server SSL context for AUX",
                sslSettingsManager.sslContextHandler(MOCK_AUX_CERT_TYPE_BAR).map(SslContextHandler::sslContext).map(SslContext::isServer).orElse(false)
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
        securitySettings.setString(MOCK_AUX_CERT_TYPE_FOO.sslSettingPrefix() + "pemkey_password_secure", certificatesRule.privateKeyPassword());

        final var settingsBuilder = defaultSettingsBuilder().setSecureSettings(securitySettings);
        withTransportSslSettings(settingsBuilder);
        withHttpSslSettings(settingsBuilder);
        withAuxFooSslSettings(settingsBuilder);

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
            sslSettingsManager.sslContextHandler(MOCK_AUX_CERT_TYPE_FOO).map(SslContextHandler::sslContext).map(SslContext::isServer).orElse(false)
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

        final var settingsBuilder = defaultSettingsBuilder().setSecureSettings(securitySettings);
        withTransportSslSettings(settingsBuilder);

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
