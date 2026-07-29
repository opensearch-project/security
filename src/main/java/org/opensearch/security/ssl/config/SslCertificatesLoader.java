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
import java.util.Locale;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.security.support.PemKeyReader;

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
        final boolean isPkcs11Keystore = PemKeyReader.PKCS11.equalsIgnoreCase(environment.settings().get(sslConfigSuffix + KEYSTORE_TYPE));
        final boolean isPkcs11Truststore = PemKeyReader.PKCS11.equalsIgnoreCase(
            environment.settings().get(sslConfigSuffix + TRUSTSTORE_TYPE)
        );
        if (settings.hasValue(sslConfigSuffix + KEYSTORE_FILEPATH) || isPkcs11Keystore) {
            final var keyStorePassword = resolvePassword(sslConfigSuffix + KEYSTORE_PASSWORD, settings, defaultStorePassword());
            return Tuple.tuple(
                environment.settings().hasValue(sslConfigSuffix + TRUSTSTORE_FILEPATH) || isPkcs11Truststore
                    ? buildTrustStoreConfiguration(
                        sslConfigSettings,
                        environment,
                        resolvePassword(sslConfigSuffix + TRUSTSTORE_PASSWORD, settings, defaultStorePassword())
                    )
                    : TrustStoreConfiguration.EMPTY_CONFIGURATION,
                buildKeyStoreConfiguration(
                    sslConfigSettings,
                    environment,
                    keyStorePassword,
                    // the key password defaults to the store password, as keytool does when only one is given
                    resolvePassword(fullSslConfigSuffix + KEYSTORE_KEY_PASSWORD, settings, keyStorePassword)
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
                    resolvePassword(fullSslConfigSuffix + PEM_KEY_PASSWORD, settings, StorePassword.NONE)
                )
            );
        }
    }

    /**
     * @return a fresh instance each time, so that the key store and the trust store never end up sharing one array
     */
    private static StorePassword defaultStorePassword() {
        return StorePassword.of(DEFAULT_STORE_PASSWORD.toCharArray());
    }

    /**
     * Resolves a password from the secure settings, falling back to the legacy plain-text setting and finally to
     * {@code defaultPassword}. The default is applied only once neither source provided a value, so that "unset"
     * stays distinguishable from "explicitly set to the default value".
     * <p>
     * The password never becomes a {@link String}: that would place a critical security parameter into memory
     * that cannot be overwritten.
     *
     * @param defaultPassword returned as is when the password is configured nowhere, {@link StorePassword#NONE}
     * where there is no password to fall back to
     */
    private StorePassword resolvePassword(
        final String legacyPasswordSettings,
        final Settings settings,
        final StorePassword defaultPassword
    ) {
        final var securePasswordSetting = String.format("%s%s", legacyPasswordSettings, SECURE_SUFFIX);
        final var securePassword = SecureSetting.secureString(securePasswordSetting, null).get(settings);
        final var legacyPassword = settings.get(legacyPasswordSettings);
        if (!securePassword.isEmpty() && legacyPassword != null) {
            throw new OpenSearchException("One of " + legacyPasswordSettings + " or " + securePasswordSetting + " must be set not both");
        }
        if (!securePassword.isEmpty()) {
            return StorePassword.of(securePassword.getChars());
        }
        if (legacyPassword != null) {
            LOGGER.warn(
                "Setting [{}] has a secure counterpart [{}] which should be used instead - allowing for legacy SSL setups",
                legacyPasswordSettings,
                securePasswordSetting
            );
            return StorePassword.of(legacyPassword.toCharArray());
        }
        return defaultPassword;
    }

    private KeyStoreConfiguration buildKeyStoreConfiguration(
        final Settings settings,
        final Environment environment,
        final StorePassword keyStorePassword,
        final StorePassword keyPassword
    ) {
        final String alias = settings.get(KEYSTORE_ALIAS, null);
        final String explicitType = environment.settings().get(sslConfigSuffix + KEYSTORE_TYPE);
        if (PemKeyReader.PKCS11.equalsIgnoreCase(explicitType)) {
            if (alias != null) {
                LOGGER.warn(
                    "Setting [{}{}] selects the certificates reported for the PKCS#11 token, but not the key used to "
                        + "handshake with - a token key cannot be extracted, so the key manager picks among all keys of the token. "
                        + "Remove the setting to silence this warning, and let the token slot this node logs into hold only the "
                        + "key it should use",
                    fullSslConfigSuffix,
                    KEYSTORE_ALIAS
                );
            }
            return new KeyStoreConfiguration.Pkcs11KeyStoreConfiguration(alias, keyStorePassword, keyPassword);
        }
        final Path path = resolvePath(environment.settings().get(sslConfigSuffix + KEYSTORE_FILEPATH), environment);
        final String resolvedType = PemKeyReader.extractStoreType(path.toString(), explicitType).toUpperCase(Locale.ROOT);
        return new KeyStoreConfiguration.JdkKeyStoreConfiguration(path, resolvedType, alias, keyStorePassword, keyPassword);
    }

    private TrustStoreConfiguration buildTrustStoreConfiguration(
        final Settings settings,
        final Environment environment,
        final StorePassword trustStorePassword
    ) {
        final String alias = settings.get(TRUSTSTORE_ALIAS, null);
        final String explicitType = environment.settings().get(sslConfigSuffix + TRUSTSTORE_TYPE);
        if (PemKeyReader.PKCS11.equalsIgnoreCase(explicitType)) {
            return new TrustStoreConfiguration.Pkcs11TrustStoreConfiguration(alias, trustStorePassword);
        }
        final Path path = resolvePath(environment.settings().get(sslConfigSuffix + TRUSTSTORE_FILEPATH), environment);
        final String resolvedType = PemKeyReader.extractStoreType(path.toString(), explicitType).toUpperCase(Locale.ROOT);
        return new TrustStoreConfiguration.JdkTrustStoreConfiguration(path, resolvedType, alias, trustStorePassword);
    }

    private KeyStoreConfiguration.PemKeyStoreConfiguration buildPemKeyStoreConfiguration(
        final Settings settings,
        final Environment environment,
        final StorePassword pemKeyPassword
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
