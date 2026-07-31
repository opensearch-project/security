/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.ssl.config;

import java.util.List;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.env.TestEnvironment;
import org.opensearch.security.support.PemKeyReader;
import org.opensearch.test.MockLogAppender;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_TYPE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_TYPE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_HTTP_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_SERVER_EXTENDED_PREFIX;

public class Pkcs11SslCertificatesLoaderTest extends SslCertificatesLoaderTest {

    static final String TOKEN_ALIAS = "token-key-alias";

    @Test
    public void loadsKeyAndTrustStoreFromTheTokenWithoutAnyFile() throws Exception {
        final var settings = defaultSettingsBuilder().put(SECURITY_SSL_HTTP_KEYSTORE_TYPE, PemKeyReader.PKCS11)
            .put(SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, PemKeyReader.PKCS11)
            .put(SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS, TOKEN_ALIAS)
            .build();

        final var configuration = new SslCertificatesLoader(SSL_HTTP_PREFIX).loadConfiguration(TestEnvironment.newEnvironment(settings));
        final var trustStoreConfiguration = configuration.v1();

        assertThat(trustStoreConfiguration, instanceOf(TrustStoreConfiguration.Pkcs11TrustStoreConfiguration.class));
        assertThat(((TrustStoreConfiguration.Pkcs11TrustStoreConfiguration) trustStoreConfiguration).alias(), is(TOKEN_ALIAS));

        assertThat(trustStoreConfiguration.files(), is(empty()));
        assertThat(configuration.v2().files(), is(empty()));
    }

    @Test
    public void storeTypeIsRecognizedRegardlessOfCase() throws Exception {
        for (final var spelling : List.of("pkcs11", "PKCS11", "Pkcs11")) {
            final var settings = defaultSettingsBuilder().put(SECURITY_SSL_HTTP_KEYSTORE_TYPE, spelling)
                .put(SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, spelling)
                .build();

            final var configuration = new SslCertificatesLoader(SSL_HTTP_PREFIX).loadConfiguration(
                TestEnvironment.newEnvironment(settings)
            );

            assertThat(spelling, configuration.v2(), instanceOf(KeyStoreConfiguration.Pkcs11KeyStoreConfiguration.class));
            assertThat(spelling, configuration.v1(), instanceOf(TrustStoreConfiguration.Pkcs11TrustStoreConfiguration.class));
        }
    }

    @Test
    public void warnsThatAKeyStoreAliasDoesNotSelectTheHandshakeKey() throws Exception {
        final var settings = defaultSettingsBuilder().put(SECURITY_SSL_HTTP_KEYSTORE_TYPE, PemKeyReader.PKCS11)
            .put(SECURITY_SSL_HTTP_KEYSTORE_ALIAS, TOKEN_ALIAS)
            .build();

        try (final var appender = MockLogAppender.createForLoggers(LogManager.getLogger(SslCertificatesLoader.class))) {
            appender.addExpectation(
                new MockLogAppender.SeenEventExpectation(
                    "names the setting and how to get rid of the warning",
                    LOGGER_NAME,
                    Level.WARN,
                    "*" + SECURITY_SSL_HTTP_KEYSTORE_ALIAS + "*not the key used to handshake with*Remove the setting*"
                )
            );

            final var keyStoreConfiguration = loadKeyStoreConfiguration(new SslCertificatesLoader(SSL_HTTP_PREFIX), settings);

            assertThat(keyStoreConfiguration, instanceOf(KeyStoreConfiguration.Pkcs11KeyStoreConfiguration.class));
            assertThat(((KeyStoreConfiguration.Pkcs11KeyStoreConfiguration) keyStoreConfiguration).alias(), is(TOKEN_ALIAS));
            appender.assertAllExpectationsMatched();
        }
    }

    /**
     * The alias is read from the extended prefix while the store type is read from the plain one, so the warning
     * has to name the setting that was actually read - {@code ...transport.server.keystore_alias}, not
     * {@code ...transport.keystore_alias}.
     */
    @Test
    public void warningNamesTheExtendedAliasSetting() throws Exception {
        final var settings = defaultSettingsBuilder().put(SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, PemKeyReader.PKCS11)
            .put(SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS, TOKEN_ALIAS)
            .build();

        try (final var appender = MockLogAppender.createForLoggers(LogManager.getLogger(SslCertificatesLoader.class))) {
            appender.addExpectation(
                new MockLogAppender.SeenEventExpectation(
                    "names the extended setting",
                    LOGGER_NAME,
                    Level.WARN,
                    "*" + SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS + "*"
                )
            );

            loadKeyStoreConfiguration(new SslCertificatesLoader(SSL_TRANSPORT_PREFIX, SSL_TRANSPORT_SERVER_EXTENDED_PREFIX), settings);

            appender.assertAllExpectationsMatched();
        }
    }

    private KeyStoreConfiguration loadKeyStoreConfiguration(final SslCertificatesLoader loader, final Settings settings) {
        return loader.loadConfiguration(TestEnvironment.newEnvironment(settings)).v2();
    }
}
