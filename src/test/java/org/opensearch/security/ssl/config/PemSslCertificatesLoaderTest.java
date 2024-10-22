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

package org.opensearch.security.ssl.config;

import java.security.SecureRandom;
import java.util.List;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.BeforeClass;
import org.junit.Test;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;

import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.env.TestEnvironment;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.ssl.CertificatesUtils.privateKeyToPemObject;
import static org.opensearch.security.ssl.CertificatesUtils.writePemContent;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_CERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_KEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_TRUSTED_CAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_HTTP_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_SERVER_EXTENDED_PREFIX;

public class PemSslCertificatesLoaderTest extends SslCertificatesLoaderTest {

    final static String PEM_CA_CERTIFICATE_FILE_NAME = "ca_certificate.pem";

    final static String PEM_KEY_CERTIFICATE_FILE_NAME = "key_certificate.pem";

    final static String PEM_CERTIFICATE_PRIVATE_KEY_FILE_NAME = "private_key.pem";

    @BeforeClass
    public static void setup() throws Exception {
        writePemContent(path(PEM_CA_CERTIFICATE_FILE_NAME), certificatesRule.caCertificateHolder());
        writePemContent(path(PEM_KEY_CERTIFICATE_FILE_NAME), certificatesRule.accessCertificateHolder());
        writePemContent(
            path(PEM_CERTIFICATE_PRIVATE_KEY_FILE_NAME),
            new PKCS8Generator(
                PrivateKeyInfo.getInstance(certificatesRule.accessCertificatePrivateKey().getEncoded()),
                new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES).setRandom(new SecureRandom())
                    .setPassword(certificatesRule.privateKeyPassword().toCharArray())
                    .build()
            ).generate()
        );
    }

    @Test
    public void loadHttpSslConfigurationFromPemFiles() throws Exception {
        testLoadPemBasedConfiguration(SSL_HTTP_PREFIX, randomBoolean());
    }

    @Test
    public void loadTransportSslConfigurationFromPemFiles() throws Exception {
        testLoadPemBasedConfiguration(SSL_HTTP_PREFIX, false);
    }

    void testLoadPemBasedConfiguration(final String sslConfigPrefix, final boolean useAuthorityCertificate) throws Exception {
        final var settingsBuilder = defaultSettingsBuilder().put(sslConfigPrefix + ENABLED, true)
            .put(sslConfigPrefix + PEM_CERT_FILEPATH, path(PEM_KEY_CERTIFICATE_FILE_NAME))
            .put(sslConfigPrefix + PEM_KEY_FILEPATH, path(PEM_CERTIFICATE_PRIVATE_KEY_FILE_NAME));
        if (useAuthorityCertificate) {
            settingsBuilder.put(sslConfigPrefix + PEM_TRUSTED_CAS_FILEPATH, path(PEM_CA_CERTIFICATE_FILE_NAME));
        }
        if (randomBoolean()) {
            final var securitySettings = new MockSecureSettings();
            securitySettings.setString(sslConfigPrefix + "pemkey_password_secure", certificatesRule.privateKeyPassword());
            settingsBuilder.setSecureSettings(securitySettings);
        } else {
            settingsBuilder.put(sslConfigPrefix + "pemkey_password", certificatesRule.privateKeyPassword());
        }

        final var settings = settingsBuilder.build();
        final var configuration = new SslCertificatesLoader(SSL_HTTP_PREFIX).loadConfiguration(TestEnvironment.newEnvironment(settings));
        if (useAuthorityCertificate) {
            assertTrustStoreConfiguration(
                configuration.v1(),
                path(PEM_CA_CERTIFICATE_FILE_NAME),
                new Certificate(certificatesRule.x509CaCertificate(), false)
            );
        } else {
            assertThat(configuration.v1(), is(TrustStoreConfiguration.EMPTY_CONFIGURATION));
        }
        assertKeyStoreConfiguration(
            configuration.v2(),
            List.of(path(PEM_KEY_CERTIFICATE_FILE_NAME), path(PEM_CERTIFICATE_PRIVATE_KEY_FILE_NAME)),
            new Certificate(certificatesRule.x509AccessCertificate(), true)
        );
    }

    @Test
    public void loadExtendedTransportSslConfigurationFromPemFiles() throws Exception {
        final var keyPair = certificatesRule.generateKeyPair();
        final var clientCaCertificate = certificatesRule.generateCaCertificate(keyPair);
        final var keyAndCertificate = certificatesRule.generateAccessCertificate(keyPair);
        final var clientCaCertificatePath = "client_ca_certificate.pem";
        final var clientKeyCertificatePath = "client_key_certificate.pem";
        final var clientPrivateKeyCertificatePath = "client_private_key_certificate.pem";
        final var clientPrivateKeyPassword = RandomStringUtils.randomAlphabetic(10);

        writePemContent(path(clientCaCertificatePath), clientCaCertificate);
        writePemContent(path(clientKeyCertificatePath), keyAndCertificate.v2());
        writePemContent(path(clientPrivateKeyCertificatePath), privateKeyToPemObject(keyAndCertificate.v1(), clientPrivateKeyPassword));

        final var settingsBuilder = defaultSettingsBuilder().put(SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED, true)
            .put(SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH, path(PEM_CA_CERTIFICATE_FILE_NAME))
            .put(SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH, path(PEM_KEY_CERTIFICATE_FILE_NAME))
            .put(SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH, path(PEM_CERTIFICATE_PRIVATE_KEY_FILE_NAME))

            .put(SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH, path(clientCaCertificatePath))
            .put(SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH, path(clientKeyCertificatePath))
            .put(SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH, path(clientPrivateKeyCertificatePath));
        if (randomBoolean()) {
            final var securitySettings = new MockSecureSettings();
            securitySettings.setString(SSL_TRANSPORT_PREFIX + "server.pemkey_password_secure", certificatesRule.privateKeyPassword());
            securitySettings.setString(SSL_TRANSPORT_PREFIX + "client.pemkey_password_secure", clientPrivateKeyPassword);
            settingsBuilder.setSecureSettings(securitySettings);
        } else {
            settingsBuilder.put(SSL_TRANSPORT_PREFIX + "server.pemkey_password", certificatesRule.privateKeyPassword());
            settingsBuilder.put(SSL_TRANSPORT_PREFIX + "client.pemkey_password", clientPrivateKeyPassword);
        }
        final var settings = settingsBuilder.build();

        final var transportServerConfiguration = new SslCertificatesLoader(SSL_TRANSPORT_PREFIX, SSL_TRANSPORT_SERVER_EXTENDED_PREFIX)
            .loadConfiguration(TestEnvironment.newEnvironment(settings));
        assertTrustStoreConfiguration(
            transportServerConfiguration.v1(),
            path(PEM_CA_CERTIFICATE_FILE_NAME),
            new Certificate(certificatesRule.x509CaCertificate(), false)
        );
        assertKeyStoreConfiguration(
            transportServerConfiguration.v2(),
            List.of(path(PEM_KEY_CERTIFICATE_FILE_NAME), path(PEM_CERTIFICATE_PRIVATE_KEY_FILE_NAME)),
            new Certificate(certificatesRule.x509AccessCertificate(), true)
        );
        final var transportClientConfiguration = new SslCertificatesLoader(SSL_TRANSPORT_PREFIX, SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX)
            .loadConfiguration(TestEnvironment.newEnvironment(settings));
        assertTrustStoreConfiguration(
            transportClientConfiguration.v1(),
            path(clientCaCertificatePath),
            new Certificate(certificatesRule.toX509Certificate(clientCaCertificate), false)
        );
        assertKeyStoreConfiguration(
            transportClientConfiguration.v2(),
            List.of(path(clientKeyCertificatePath), path(clientPrivateKeyCertificatePath)),
            new Certificate(certificatesRule.toX509Certificate(keyAndCertificate.v2()), true)
        );
    }

}
