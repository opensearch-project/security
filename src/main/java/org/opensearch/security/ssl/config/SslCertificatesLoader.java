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
        final var keyStoreType = settings.get(sslConfigSuffix + KEYSTORE_TYPE);
        final var trustStoreType = settings.get(sslConfigSuffix + TRUSTSTORE_TYPE);
        final boolean isPkcs11Keystore = PemKeyReader.PKCS11.equalsIgnoreCase(keyStoreType);
        final boolean isPkcs11Truststore = PemKeyReader.PKCS11.equalsIgnoreCase(trustStoreType);
        final boolean usesKeyStore = settings.hasValue(sslConfigSuffix + KEYSTORE_FILEPATH) || isPkcs11Keystore;
        final boolean usesTrustStore = settings.hasValue(sslConfigSuffix + TRUSTSTORE_FILEPATH) || isPkcs11Truststore;
        final boolean usesPemTrustedCas = sslConfigSettings.hasValue(PEM_TRUSTED_CAS_FILEPATH);
        if (usesKeyStore) {
            warnIfPemTrustedCasAreIgnored(usesPemTrustedCas);
            final var keyStorePassword = resolvePassword(sslConfigSuffix + KEYSTORE_PASSWORD, settings, defaultStorePassword());
            final var trustStoreConfiguration = usesTrustStore
                ? TrustStoreConfiguration.buildTrustStoreConfiguration(
                    trustStoreType,
                    () -> resolvePath(settings.get(sslConfigSuffix + TRUSTSTORE_FILEPATH), environment),
                    sslConfigSettings.get(TRUSTSTORE_ALIAS, null),
                    resolvePassword(sslConfigSuffix + TRUSTSTORE_PASSWORD, settings, defaultStorePassword())
                )
                : TrustStoreConfiguration.EMPTY_CONFIGURATION;
            final var keyStoreConfiguration = KeyStoreConfiguration.buildKeyStoreConfiguration(
                keyStoreType,
                () -> resolvePath(settings.get(sslConfigSuffix + KEYSTORE_FILEPATH), environment),
                sslConfigSettings.get(KEYSTORE_ALIAS, null),
                keyStorePassword,
                // the key password defaults to the store password, as keytool does when only one is given
                resolvePassword(fullSslConfigSuffix + KEYSTORE_KEY_PASSWORD, settings, keyStorePassword)
            );
            warnIfTokenAliasCannotSelectTheKey(keyStoreConfiguration);
            return Tuple.tuple(trustStoreConfiguration, keyStoreConfiguration);
        } else {
            warnIfTrustStoreSettingsAreIgnored(usesTrustStore);
            final var trustStoreConfiguration = usesPemTrustedCas
                ? new TrustStoreConfiguration.PemTrustStoreConfiguration(
                    resolvePath(sslConfigSettings.get(PEM_TRUSTED_CAS_FILEPATH), environment)
                )
                : TrustStoreConfiguration.EMPTY_CONFIGURATION;
            final var keyStoreConfiguration = new KeyStoreConfiguration.PemKeyStoreConfiguration(
                resolvePath(sslConfigSettings.get(PEM_CERT_FILEPATH), environment),
                resolvePath(sslConfigSettings.get(PEM_KEY_FILEPATH), environment),
                resolvePassword(fullSslConfigSuffix + PEM_KEY_PASSWORD, settings, StorePassword.NONE)
            );
            return Tuple.tuple(trustStoreConfiguration, keyStoreConfiguration);
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

    /**
     * The trusted certificates of a key store configuration are read from a store as well, so PEM ones are dropped -
     * and the peer verification falls back to whatever the TLS engine defaults to, rather than using the certificates
     * that were configured.
     */
    private void warnIfPemTrustedCasAreIgnored(final boolean usesPemTrustedCas) {
        if (!usesPemTrustedCas) {
            return;
        }
        LOGGER.warn(
            "Setting [{}{}] is ignored because the key material comes from a key store - configure the trusted "
                + "certificates in [{}{}], or in a PKCS#11 token via [{}{}], to have this node actually use them",
            fullSslConfigSuffix,
            PEM_TRUSTED_CAS_FILEPATH,
            sslConfigSuffix,
            TRUSTSTORE_FILEPATH,
            sslConfigSuffix,
            TRUSTSTORE_TYPE
        );
    }

    /**
     * The counterpart of {@link #warnIfPemTrustedCasAreIgnored(boolean)}: PEM key material reads its trusted
     * certificates from a PEM file, so a trust store or token configured alongside it is dropped.
     */
    private void warnIfTrustStoreSettingsAreIgnored(final boolean usesTrustStore) {
        if (!usesTrustStore) {
            return;
        }
        LOGGER.warn(
            "Settings [{}{}] and [{}{}] are ignored because the key material comes from PEM files - configure the "
                + "trusted certificates in [{}{}] to have this node actually use them",
            sslConfigSuffix,
            TRUSTSTORE_FILEPATH,
            sslConfigSuffix,
            TRUSTSTORE_TYPE,
            fullSslConfigSuffix,
            PEM_TRUSTED_CAS_FILEPATH
        );
    }

    private void warnIfTokenAliasCannotSelectTheKey(final KeyStoreConfiguration keyStoreConfiguration) {
        if (keyStoreConfiguration instanceof KeyStoreConfiguration.Pkcs11KeyStoreConfiguration token && token.alias() != null) {
            LOGGER.warn(
                "Setting [{}{}] selects the certificates reported for the PKCS#11 token, but not the key used to "
                    + "handshake with - a token key cannot be extracted, so the key manager picks among all keys of the token. "
                    + "Remove the setting to silence this warning, and let the token slot this node logs into hold only the "
                    + "key it should use",
                fullSslConfigSuffix,
                KEYSTORE_ALIAS
            );
        }
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
