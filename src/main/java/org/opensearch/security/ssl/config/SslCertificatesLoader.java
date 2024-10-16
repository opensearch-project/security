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
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.KeyStore;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;

import static org.opensearch.security.ssl.SecureSSLSettings.SECURE_SUFFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.DEFAULT_STORE_PASSWORD;
import static org.opensearch.security.ssl.util.SSLConfigConstants.KEYSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.KEYSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.KEYSTORE_KEY_PASSWORD;
import static org.opensearch.security.ssl.util.SSLConfigConstants.KEYSTORE_PASSWORD;
import static org.opensearch.security.ssl.util.SSLConfigConstants.KEYSTORE_TYPE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_CERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_KEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_KEY_PASSWORD;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_TRUSTED_CAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.TRUSTSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.TRUSTSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.TRUSTSTORE_PASSWORD;
import static org.opensearch.security.ssl.util.SSLConfigConstants.TRUSTSTORE_TYPE;

public class SslCertificatesLoader {

    private final static Logger LOGGER = LogManager.getLogger(SslCertificatesLoader.class);

    private final String sslConfigSuffix;

    private final String fullSslConfigSuffix;

    public SslCertificatesLoader(final String sslConfigSuffix) {
        this(sslConfigSuffix, null);
    }

    public SslCertificatesLoader(final String sslConfigSuffix, final String extendedSslConfigSuffix) {
        this.sslConfigSuffix = sslConfigSuffix;
        this.fullSslConfigSuffix = extendedSslConfigSuffix != null ? sslConfigSuffix + extendedSslConfigSuffix : sslConfigSuffix;
    }

    public Tuple<TrustStoreConfiguration, KeyStoreConfiguration> loadConfiguration(final Environment environment) {
        final var settings = environment.settings();
        final var sslConfigSettings = settings.getByPrefix(fullSslConfigSuffix);
        if (settings.hasValue(sslConfigSuffix + KEYSTORE_FILEPATH)) {
            return Tuple.tuple(
                environment.settings().hasValue(sslConfigSuffix + TRUSTSTORE_FILEPATH)
                    ? buildJdkTrustStoreConfiguration(
                        sslConfigSettings,
                        environment,
                        resolvePassword(sslConfigSuffix + TRUSTSTORE_PASSWORD, settings, DEFAULT_STORE_PASSWORD)
                    )
                    : TrustStoreConfiguration.EMPTY_CONFIGURATION,
                buildJdkKeyStoreConfiguration(
                    sslConfigSettings,
                    environment,
                    resolvePassword(sslConfigSuffix + KEYSTORE_PASSWORD, settings, DEFAULT_STORE_PASSWORD),
                    resolvePassword(fullSslConfigSuffix + KEYSTORE_KEY_PASSWORD, settings, DEFAULT_STORE_PASSWORD)
                )
            );
        } else {
            return Tuple.tuple(
                sslConfigSettings.hasValue(PEM_TRUSTED_CAS_FILEPATH)
                    ? new TrustStoreConfiguration.PemTrustStoreConfiguration(
                        resolvePath(sslConfigSettings.get(PEM_TRUSTED_CAS_FILEPATH), environment)
                    )
                    : TrustStoreConfiguration.EMPTY_CONFIGURATION,
                buildPemKeyStoreConfiguration(
                    sslConfigSettings,
                    environment,
                    resolvePassword(fullSslConfigSuffix + PEM_KEY_PASSWORD, settings, null)
                )
            );
        }
    }

    private char[] resolvePassword(final String legacyPasswordSettings, final Settings settings, final String defaultPassword) {
        final var securePasswordSetting = String.format("%s%s", legacyPasswordSettings, SECURE_SUFFIX);
        final var securePassword = SecureSetting.secureString(securePasswordSetting, null).get(settings);
        final var legacyPassword = settings.get(legacyPasswordSettings, defaultPassword);
        if (!securePassword.isEmpty() && legacyPassword != null && !legacyPassword.equals(defaultPassword)) {
            throw new OpenSearchException("One of " + legacyPasswordSettings + " or " + securePasswordSetting + " must be set not both");
        }
        if (!securePassword.isEmpty()) {
            return securePassword.getChars();
        } else {
            if (legacyPassword != null) {
                LOGGER.warn(
                    "Setting [{}] has a secure counterpart [{}] which should be used instead - allowing for legacy SSL setups",
                    legacyPasswordSettings,
                    securePasswordSetting
                );
                return legacyPassword.toCharArray();
            }
        }
        return null;
    }

    private KeyStoreConfiguration.JdkKeyStoreConfiguration buildJdkKeyStoreConfiguration(
        final Settings settings,
        final Environment environment,
        final char[] keyStorePassword,
        final char[] keyPassword
    ) {
        return new KeyStoreConfiguration.JdkKeyStoreConfiguration(
            resolvePath(environment.settings().get(sslConfigSuffix + KEYSTORE_FILEPATH), environment),
            environment.settings().get(sslConfigSuffix + KEYSTORE_TYPE, KeyStore.getDefaultType()),
            settings.get(KEYSTORE_ALIAS, null),
            keyStorePassword,
            keyPassword
        );
    }

    private TrustStoreConfiguration.JdkTrustStoreConfiguration buildJdkTrustStoreConfiguration(
        final Settings settings,
        final Environment environment,
        final char[] trustStorePassword
    ) {
        return new TrustStoreConfiguration.JdkTrustStoreConfiguration(
            resolvePath(environment.settings().get(sslConfigSuffix + TRUSTSTORE_FILEPATH), environment),
            environment.settings().get(sslConfigSuffix + TRUSTSTORE_TYPE, KeyStore.getDefaultType()),
            settings.get(TRUSTSTORE_ALIAS, null),
            trustStorePassword
        );
    }

    private KeyStoreConfiguration.PemKeyStoreConfiguration buildPemKeyStoreConfiguration(
        final Settings settings,
        final Environment environment,
        final char[] pemKeyPassword
    ) {
        return new KeyStoreConfiguration.PemKeyStoreConfiguration(
            resolvePath(settings.get(PEM_CERT_FILEPATH), environment),
            resolvePath(settings.get(PEM_KEY_FILEPATH), environment),
            pemKeyPassword
        );
    }

    private Path resolvePath(final String filePath, final Environment environment) {
        final var path = environment.configDir().resolve(Path.of(filePath));
        if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new OpenSearchException(filePath + " - is a directory");
        }
        if (!Files.isReadable(path)) {
            throw new OpenSearchException(
                "Unable to read the file " + filePath + ". Please make sure this files exists and is readable regarding to permissions"
            );
        }
        return path;
    }

}
