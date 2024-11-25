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

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.junit.Test;

import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.env.TestEnvironment;

import static java.util.Objects.isNull;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.ssl.util.SSLConfigConstants.DEFAULT_STORE_PASSWORD;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.KEYSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.KEYSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.KEYSTORE_TYPE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_HTTP_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_SERVER_EXTENDED_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.TRUSTSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.TRUSTSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.TRUSTSTORE_TYPE;

public class JdkSslCertificatesLoaderTest extends SslCertificatesLoaderTest {

    static final Function<String, String> resolveKeyStoreType = s -> isNull(s) ? KeyStore.getDefaultType() : s;

    static final String SERVER_TRUSTSTORE_ALIAS = "server-truststore-alias";

    static final String SERVER_KEYSTORE_ALIAS = "server-keystore-alias";

    static final String CLIENT_TRUSTSTORE_ALIAS = "client-truststore-alias";

    static final String CLIENT_KEYSTORE_ALIAS = "client-keystore-alias";

    @Test
    public void loadHttpSslConfigurationFromKeyAndTrustStoreFiles() throws Exception {
        testJdkBasedSslConfiguration(SSL_HTTP_PREFIX, randomBoolean());
    }

    @Test
    public void loadTransportJdkBasedSslConfiguration() throws Exception {
        testJdkBasedSslConfiguration(SSL_TRANSPORT_PREFIX, true);
    }

    @Test
    public void loadTransportJdkBasedSslExtendedConfiguration() throws Exception {
        final var clientKeyPair = certificatesRule.generateKeyPair();

        final var serverCaCertificate = certificatesRule.x509CaCertificate();
        final var clientCaCertificate = certificatesRule.toX509Certificate(certificatesRule.generateCaCertificate(clientKeyPair));

        final var serverAccessCertificateKey = certificatesRule.accessCertificatePrivateKey();
        final var serverAccessCertificate = certificatesRule.x509AccessCertificate();

        final var clientAccessCertificateAndKey = certificatesRule.generateAccessCertificate(clientKeyPair);

        final var clientAccessCertificateKey = clientAccessCertificateAndKey.v1();
        final var clientAccessCertificate = certificatesRule.toX509Certificate(clientAccessCertificateAndKey.v2());

        final var trustStoreType = randomKeyStoreType();
        final var keyStoreType = randomKeyStoreType();

        final var useSecurePassword = randomBoolean();
        final var trustStorePassword = randomKeyStorePassword(useSecurePassword);
        final var keyStorePassword = randomKeyStorePassword(useSecurePassword);

        final var trustStorePath = createTrustStore(
            trustStoreType,
            trustStorePassword,
            Map.of(SERVER_TRUSTSTORE_ALIAS, serverCaCertificate, CLIENT_TRUSTSTORE_ALIAS, clientCaCertificate)
        );
        final var keyStorePath = createKeyStore(
            keyStoreType,
            keyStorePassword,
            Map.of(
                SERVER_KEYSTORE_ALIAS,
                Tuple.tuple(serverAccessCertificateKey, serverAccessCertificate),
                CLIENT_KEYSTORE_ALIAS,
                Tuple.tuple(clientAccessCertificateKey, clientAccessCertificate)
            )
        );

        final var settingsBuilder = defaultSettingsBuilder().put(SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED, true)
            .put(SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE, trustStoreType)
            .put(SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, trustStorePath)
            .put(SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS, SERVER_TRUSTSTORE_ALIAS)
            .put(SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS, CLIENT_TRUSTSTORE_ALIAS)
            .put(SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, keyStoreType)
            .put(SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, keyStorePath)
            .put(SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS, SERVER_KEYSTORE_ALIAS)
            .put(SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS, CLIENT_KEYSTORE_ALIAS);

        if (useSecurePassword) {
            final var securitySettings = new MockSecureSettings();
            securitySettings.setString(SSL_TRANSPORT_PREFIX + "keystore_password_secure", keyStorePassword);
            securitySettings.setString(SSL_TRANSPORT_PREFIX + "truststore_password_secure", trustStorePassword);

            securitySettings.setString(
                SSL_TRANSPORT_PREFIX + SSL_TRANSPORT_SERVER_EXTENDED_PREFIX + "keystore_keypassword_secure",
                certificatesRule.privateKeyPassword()
            );
            securitySettings.setString(
                SSL_TRANSPORT_PREFIX + SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX + "keystore_keypassword_secure",
                certificatesRule.privateKeyPassword()
            );
            settingsBuilder.setSecureSettings(securitySettings);
        } else {
            settingsBuilder.put(SSL_TRANSPORT_PREFIX + "keystore_password", keyStorePassword);
            settingsBuilder.put(SSL_TRANSPORT_PREFIX + "truststore_password", trustStorePassword);

            settingsBuilder.put(
                SSL_TRANSPORT_PREFIX + SSL_TRANSPORT_SERVER_EXTENDED_PREFIX + "keystore_keypassword",
                certificatesRule.privateKeyPassword()
            );
            settingsBuilder.put(
                SSL_TRANSPORT_PREFIX + SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX + "keystore_keypassword",
                certificatesRule.privateKeyPassword()
            );
        }
        final var settings = settingsBuilder.build();

        final var serverConfiguration = new SslCertificatesLoader(SSL_TRANSPORT_PREFIX, SSL_TRANSPORT_SERVER_EXTENDED_PREFIX)
            .loadConfiguration(TestEnvironment.newEnvironment(settings));
        assertTrustStoreConfiguration(
            serverConfiguration.v1(),
            trustStorePath,
            new Certificate(serverCaCertificate, resolveKeyStoreType.apply(trustStoreType), SERVER_TRUSTSTORE_ALIAS, false)
        );
        assertKeyStoreConfiguration(
            serverConfiguration.v2(),
            List.of(keyStorePath),
            new Certificate(serverAccessCertificate, resolveKeyStoreType.apply(keyStoreType), SERVER_KEYSTORE_ALIAS, true)
        );

        final var clientConfiguration = new SslCertificatesLoader(SSL_TRANSPORT_PREFIX, SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX)
            .loadConfiguration(TestEnvironment.newEnvironment(settings));
        assertTrustStoreConfiguration(
            clientConfiguration.v1(),
            trustStorePath,
            new Certificate(clientCaCertificate, resolveKeyStoreType.apply(trustStoreType), CLIENT_TRUSTSTORE_ALIAS, false)
        );
        assertKeyStoreConfiguration(
            clientConfiguration.v2(),
            List.of(keyStorePath),
            new Certificate(clientAccessCertificate, resolveKeyStoreType.apply(keyStoreType), CLIENT_KEYSTORE_ALIAS, true)
        );
    }

    private void testJdkBasedSslConfiguration(final String sslConfigPrefix, final boolean useAuthorityCertificate) throws Exception {
        final var useSecurePassword = randomBoolean();

        final var keyPair = certificatesRule.generateKeyPair();
        final var trustStoreCertificates = Map.of(
            "default-truststore-alias",
            certificatesRule.x509CaCertificate(),
            "another-truststore-alias",
            certificatesRule.toX509Certificate(certificatesRule.generateCaCertificate(keyPair))
        );

        final var keysAndCertificate = certificatesRule.generateAccessCertificate(keyPair);
        final var keyStoreCertificates = Map.of(
            "default-keystore-alias",
            Tuple.tuple(certificatesRule.accessCertificatePrivateKey(), certificatesRule.x509AccessCertificate()),
            "another-keystore-alias",
            Tuple.tuple(keysAndCertificate.v1(), certificatesRule.toX509Certificate(keysAndCertificate.v2()))
        );

        final var trustStoreAlias = randomFrom(new String[] { "default-truststore-alias", "another-truststore-alias", null });
        final var keyStoreAlias = (String) null;// randomFrom(new String[] { "default-keystore-alias", "another-keystore-alias", null });

        final var keyStorePassword = randomKeyStorePassword(useSecurePassword);
        final var trustStorePassword = randomKeyStorePassword(useSecurePassword);

        final var keyStoreType = randomKeyStoreType();
        final var keyStorePath = createKeyStore(keyStoreType, keyStorePassword, keyStoreCertificates);

        final var trustStoreType = randomKeyStoreType();
        final var trustStorePath = createTrustStore(trustStoreType, trustStorePassword, trustStoreCertificates);

        final var settingsBuilder = defaultSettingsBuilder().put(sslConfigPrefix + ENABLED, true)
            .put(sslConfigPrefix + KEYSTORE_FILEPATH, keyStorePath)
            .put(sslConfigPrefix + KEYSTORE_ALIAS, keyStoreAlias)
            .put(sslConfigPrefix + KEYSTORE_TYPE, keyStoreType);
        if (useAuthorityCertificate) {
            settingsBuilder.put(sslConfigPrefix + TRUSTSTORE_FILEPATH, trustStorePath)
                .put(sslConfigPrefix + TRUSTSTORE_ALIAS, trustStoreAlias)
                .put(sslConfigPrefix + TRUSTSTORE_TYPE, trustStoreType);
        }
        if (useSecurePassword) {
            final var securitySettings = new MockSecureSettings();
            securitySettings.setString(sslConfigPrefix + "keystore_password_secure", keyStorePassword);
            securitySettings.setString(sslConfigPrefix + "keystore_keypassword_secure", certificatesRule.privateKeyPassword());
            if (useAuthorityCertificate) {
                securitySettings.setString(sslConfigPrefix + "truststore_password_secure", trustStorePassword);
            }
            settingsBuilder.setSecureSettings(securitySettings);
        } else {
            settingsBuilder.put(sslConfigPrefix + "keystore_password", keyStorePassword);
            settingsBuilder.put(sslConfigPrefix + "keystore_keypassword", certificatesRule.privateKeyPassword());
            if (useAuthorityCertificate) {
                settingsBuilder.put(sslConfigPrefix + "truststore_password", trustStorePassword);
            }
        }

        final var configuration = new SslCertificatesLoader(sslConfigPrefix).loadConfiguration(
            TestEnvironment.newEnvironment(settingsBuilder.build())
        );

        if (useAuthorityCertificate) {
            final var expectedTrustStoreCertificates = isNull(trustStoreAlias)
                ? trustStoreCertificates.entrySet()
                    .stream()
                    .map(e -> new Certificate(e.getValue(), resolveKeyStoreType.apply(trustStoreType), e.getKey(), false))
                    .toArray(Certificate[]::new)
                : trustStoreCertificates.entrySet()
                    .stream()
                    .filter(e -> e.getKey().equals(trustStoreAlias))
                    .map(e -> new Certificate(e.getValue(), resolveKeyStoreType.apply(trustStoreType), e.getKey(), false))
                    .toArray(Certificate[]::new);
            assertTrustStoreConfiguration(configuration.v1(), trustStorePath, expectedTrustStoreCertificates);
        } else {
            assertThat(configuration.v1(), is(TrustStoreConfiguration.EMPTY_CONFIGURATION));
        }

        final var expectedKeyStoreCertificates = isNull(keyStoreAlias)
            ? keyStoreCertificates.entrySet()
                .stream()
                .map(e -> new Certificate(e.getValue().v2(), resolveKeyStoreType.apply(keyStoreType), e.getKey(), true))
                .toArray(Certificate[]::new)
            : keyStoreCertificates.entrySet()
                .stream()
                .filter(e -> e.getKey().equals(keyStoreAlias))
                .map(e -> new Certificate(e.getValue().v2(), resolveKeyStoreType.apply(keyStoreType), e.getKey(), true))
                .toArray(Certificate[]::new);
        assertKeyStoreConfiguration(configuration.v2(), List.of(keyStorePath), expectedKeyStoreCertificates);
    }

    String randomKeyStoreType() {
        return randomFrom(new String[] { "jks", "pkcs12", null });
    }

    String randomKeyStorePassword(final boolean useSecurePassword) {
        return useSecurePassword ? randomAsciiAlphanumOfLength(10) : randomFrom(new String[] { randomAsciiAlphanumOfLength(10), null });
    }

    Path createTrustStore(final String type, final String password, Map<String, X509Certificate> certificates) throws Exception {
        final var keyStore = keyStore(type);
        for (final var alias : certificates.keySet()) {
            keyStore.setCertificateEntry(alias, certificates.get(alias));
        }
        final var trustStorePath = path(String.format("truststore.%s", isNull(type) ? "jsk" : type));
        storeKeyStore(keyStore, trustStorePath, password);
        return trustStorePath;
    }

    Path createKeyStore(final String type, final String password, final Map<String, Tuple<PrivateKey, X509Certificate>> keysAndCertificates)
        throws Exception {
        final var keyStore = keyStore(type);
        final var keyStorePath = path(String.format("keystore.%s", isNull(type) ? "jks" : type));
        for (final var alias : keysAndCertificates.keySet()) {
            final var keyAndCertificate = keysAndCertificates.get(alias);
            keyStore.setKeyEntry(
                alias,
                keyAndCertificate.v1(),
                certificatesRule.privateKeyPassword().toCharArray(),
                new X509Certificate[] { keyAndCertificate.v2() }
            );
        }
        storeKeyStore(keyStore, keyStorePath, password);
        return keyStorePath;
    }

    KeyStore keyStore(final String type) throws Exception {
        final var keyStore = KeyStore.getInstance(isNull(type) ? KeyStore.getDefaultType() : type);
        keyStore.load(null, null);
        return keyStore;
    }

    void storeKeyStore(final KeyStore keyStore, final Path path, final String password) throws Exception {
        try (final var out = Files.newOutputStream(path)) {
            keyStore.store(out, isNull(password) ? DEFAULT_STORE_PASSWORD.toCharArray() : password.toCharArray());
        }
    }

}
