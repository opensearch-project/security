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

import java.io.IOException;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import javax.crypto.Cipher;

import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.security.ssl.config.CertType;
import org.opensearch.security.ssl.config.KeyStoreConfiguration;
import org.opensearch.security.ssl.config.SslCertificatesLoader;
import org.opensearch.security.ssl.config.SslParameters;
import org.opensearch.security.ssl.config.TrustStoreConfiguration;
import org.opensearch.watcher.FileChangesListener;
import org.opensearch.watcher.FileWatcher;
import org.opensearch.watcher.ResourceWatcherService;

import io.netty.handler.ssl.ClientAuth;

import static org.opensearch.plugins.NetworkPlugin.AuxTransport.AUX_TRANSPORT_TYPES_SETTING;
import static org.opensearch.security.ssl.config.CertType.CERT_TYPE_REGISTRY;
import static org.opensearch.security.ssl.util.SSLConfigConstants.CLIENT_AUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.EXTENDED_KEY_USAGE_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.KEYSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.KEYSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_CERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_KEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_TRUSTED_CAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_DEFAULT;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED_DEFAULT;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_AUX_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_SERVER_EXTENDED_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.TRUSTSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.TRUSTSTORE_FILEPATH;

public class SslSettingsManager {

    private final static Logger LOGGER = LogManager.getLogger(SslSettingsManager.class);

    private final Map<CertType, SslContextHandler> sslSettingsContexts;

    public SslSettingsManager(final Environment environment) {
        this.sslSettingsContexts = buildSslContexts(environment);
    }

    public Optional<SslConfiguration> sslConfiguration(final CertType certType) {
        return Optional.ofNullable(sslSettingsContexts.get(certType)).map(SslContextHandler::sslConfiguration);
    }

    public Optional<SslContextHandler> sslContextHandler(final CertType certType) {
        return Optional.ofNullable(sslSettingsContexts.get(certType));
    }

    /**
     * Load and validate environment configuration for available CertTypes.
     * @param environment settings and JDK environment.
     */
    private Map<CertType, SslContextHandler> buildSslContexts(final Environment environment) {
        final ImmutableMap.Builder<CertType, SslContextHandler> contexts = new ImmutableMap.Builder<>();
        final Map<CertType, SslConfiguration> configurations = loadConfigurations(environment);
        configurations.forEach((cert, sslConfig) -> {
            // TRANSPORT/TRANSPORT_CLIENT are exceptions.
            if (cert == CertType.TRANSPORT) {
                Optional.ofNullable(configurations.get(CertType.TRANSPORT)).ifPresentOrElse(sslConfiguration -> {
                    contexts.put(CertType.TRANSPORT, new SslContextHandler(sslConfiguration));
                    final var transportClientConfiguration = Optional.ofNullable(configurations.get(CertType.TRANSPORT_CLIENT))
                        .orElse(sslConfiguration);
                    contexts.put(CertType.TRANSPORT_CLIENT, new SslContextHandler(transportClientConfiguration, true));
                }, () -> LOGGER.warn("SSL Configuration for Transport Layer hasn't been set"));
                return;
            } else if (cert == CertType.TRANSPORT_CLIENT) {
                return; // TRANSPORT_CLIENT is handled in TRANSPORT case. Skip.
            }

            // Load all other configurations into SslContextHandlers.
            Optional.ofNullable(configurations.get(cert))
                .ifPresentOrElse(
                    sslConfiguration -> contexts.put(cert, new SslContextHandler(sslConfiguration)),
                    () -> LOGGER.warn("SSL Configuration for {} Layer hasn't been set", cert.certID())
                );
        });
        return contexts.build();
    }

    public synchronized void reloadSslContext(final CertType certType) {
        sslContextHandler(certType).ifPresentOrElse(sscContextHandler -> {
            try {
                if (sscContextHandler.reloadSslContext()) {
                    LOGGER.info("{} SSL context reloaded", certType.certID());
                }
            } catch (CertificateException e) {
                throw new OpenSearchException(e);
            }
        }, () -> LOGGER.error("Missing SSL Context for {}", certType.certID()));
    }

    private Map<CertType, SslConfiguration> loadConfigurations(final Environment environment) {
        final Settings settings = environment.settings();
        final ImmutableMap.Builder<CertType, SslConfiguration> configurationBuilder = ImmutableMap.builder();
        if (settings.getByPrefix(CertType.HTTP.sslSettingPrefix()).isEmpty()
            && settings.getByPrefix(CertType.TRANSPORT.sslSettingPrefix()).isEmpty()) {
            throw new OpenSearchException("No SSL configuration found");
        }
        jceWarnings();

        /*
         * Fetch and load configurations for available aux transports.
         * Registered all configured aux transports as new CertTypes.
         */
        for (String auxType : AUX_TRANSPORT_TYPES_SETTING.get(environment.settings())) {
            final CertType auxCert = new CertType(SSL_AUX_PREFIX + auxType + ".");
            final Setting<Boolean> auxEnabled = SECURITY_SSL_AUX_ENABLED.getConcreteSettingForNamespace(auxType);
            CERT_TYPE_REGISTRY.register(auxCert);
            if (auxEnabled.get(settings) && !clientNode(settings)) {
                validateSettings(auxCert, settings, false);
                final SslParameters auxSslParameters = SslParameters.loader(auxCert, settings).load();
                final Tuple<TrustStoreConfiguration, KeyStoreConfiguration> auxTrustAndKeyStore = new SslCertificatesLoader(
                    auxCert.sslSettingPrefix()
                ).loadConfiguration(environment);
                configurationBuilder.put(
                    auxCert,
                    new SslConfiguration(auxSslParameters, auxTrustAndKeyStore.v1(), auxTrustAndKeyStore.v2())
                );
                LOGGER.info("TLS {} Provider                    : {}", auxCert.certID(), auxSslParameters.provider());
                LOGGER.info("Enabled TLS protocols for {} layer : {}", auxCert.certID(), auxSslParameters.allowedProtocols());
            }
        }

        /*
         * Load HTTP SslConfiguration.
         */
        final boolean httpEnabled = settings.getAsBoolean(CertType.HTTP.sslSettingPrefix() + ENABLED, SECURITY_SSL_HTTP_ENABLED_DEFAULT);
        if (httpEnabled && !clientNode(settings)) {
            validateSettings(CertType.HTTP, settings, SECURITY_SSL_HTTP_ENABLED_DEFAULT);
            final var httpSslParameters = SslParameters.loader(CertType.HTTP, settings).load();
            final var httpTrustAndKeyStore = new SslCertificatesLoader(CertType.HTTP.sslSettingPrefix()).loadConfiguration(environment);
            configurationBuilder.put(
                CertType.HTTP,
                new SslConfiguration(httpSslParameters, httpTrustAndKeyStore.v1(), httpTrustAndKeyStore.v2())
            );
            LOGGER.info("TLS HTTP Provider                    : {}", httpSslParameters.provider());
            LOGGER.info("Enabled TLS protocols for HTTP layer : {}", httpSslParameters.allowedProtocols());
        }

        /*
         * Load transport layer SslConfigurations.
         */
        final Settings transportSettings = settings.getByPrefix(CertType.TRANSPORT.sslSettingPrefix());
        final SslParameters transportSslParameters = SslParameters.loader(CertType.TRANSPORT, settings).load();
        if (transportSettings.getAsBoolean(ENABLED, SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT)) {
            if (hasExtendedKeyUsageEnabled(transportSettings)) {
                validateTransportSettings(transportSettings);
                final var transportServerTrustAndKeyStore = new SslCertificatesLoader(
                    CertType.TRANSPORT.sslSettingPrefix(),
                    SSL_TRANSPORT_SERVER_EXTENDED_PREFIX
                ).loadConfiguration(environment);
                configurationBuilder.put(
                    CertType.TRANSPORT,
                    new SslConfiguration(transportSslParameters, transportServerTrustAndKeyStore.v1(), transportServerTrustAndKeyStore.v2())
                );
                final var transportClientTrustAndKeyStore = new SslCertificatesLoader(
                    CertType.TRANSPORT.sslSettingPrefix(),
                    SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX
                ).loadConfiguration(environment);
                configurationBuilder.put(
                    CertType.TRANSPORT_CLIENT,
                    new SslConfiguration(transportSslParameters, transportClientTrustAndKeyStore.v1(), transportClientTrustAndKeyStore.v2())
                );
            } else {
                validateTransportSettings(transportSettings);
                final var transportTrustAndKeyStore = new SslCertificatesLoader(CertType.TRANSPORT.sslSettingPrefix()).loadConfiguration(
                    environment
                );
                configurationBuilder.put(
                    CertType.TRANSPORT,
                    new SslConfiguration(transportSslParameters, transportTrustAndKeyStore.v1(), transportTrustAndKeyStore.v2())
                );
            }
            LOGGER.info("TLS Transport Client Provider             : {}", transportSslParameters.provider());
            LOGGER.info("TLS Transport Server Provider             : {}", transportSslParameters.provider());
            LOGGER.info("Enabled TLS protocols for Transport layer : {}", transportSslParameters.allowedProtocols());
        }
        return configurationBuilder.build();
    }

    public void addSslConfigurationsChangeListener(final ResourceWatcherService resourceWatcherService) {
        for (final var directoryToMonitor : directoriesToMonitor()) {
            final var fileWatcher = new FileWatcher(directoryToMonitor);
            fileWatcher.addListener(new FileChangesListener() {
                @Override
                public void onFileCreated(final Path file) {
                    onFileChanged(file);
                }

                @Override
                public void onFileDeleted(final Path file) {
                    onFileChanged(file);
                }

                @Override
                public void onFileChanged(final Path file) {
                    for (final var e : sslSettingsContexts.entrySet()) {
                        final var certType = e.getKey();
                        final var sslConfiguration = e.getValue().sslConfiguration();
                        if (sslConfiguration.dependentFiles().contains(file)) {
                            SslSettingsManager.this.reloadSslContext(certType);
                        }
                    }
                }
            });
            try {
                resourceWatcherService.add(fileWatcher, ResourceWatcherService.Frequency.HIGH);
                LOGGER.info("Added SSL configuration change listener for: {}", directoryToMonitor);
            } catch (IOException e) {
                // TODO: should we fail here, or are error logs sufficient?
                throw new OpenSearchException("Couldn't add SSL configurations change listener", e);
            }
        }
    }

    private Set<Path> directoriesToMonitor() {
        return sslSettingsContexts.values()
            .stream()
            .map(SslContextHandler::sslConfiguration)
            .flatMap(c -> c.dependentFiles().stream())
            .map(Path::getParent)
            .collect(Collectors.toSet());
    }

    private boolean clientNode(final Settings settings) {
        return !"node".equals(settings.get(OpenSearchSecuritySSLPlugin.CLIENT_TYPE));
    }

    /**
     * Validates configuration of transport pem store/keystore for provided CertType.
     * {@link org.opensearch.OpenSearchException} thrown on invalid config.
     * @param certType cert type to validate.
     * @param settings {@link org.opensearch.env.Environment} settings.
     */
    private void validateSettings(final CertType certType, final Settings settings, final boolean enabled_default) {
        final Settings certSettings = settings.getByPrefix(certType.sslSettingPrefix());
        if (certSettings.isEmpty()) return;
        if (!certSettings.getAsBoolean(ENABLED, enabled_default)) return;
        if (hasPemStoreSettings(certSettings)) {
            validatePemStoreSettings(certType, settings);
        } else if (hasKeyOrTrustStoreSettings(certSettings)) {
            validateKeyStoreSettings(certType, settings);
        } else {
            throw new OpenSearchException(
                "Wrong "
                    + certType.certID()
                    + " SSL configuration. One of Keystore and Truststore files or X.509 PEM certificates and "
                    + "PKCS#8 keys groups should be set to configure "
                    + certType.certID()
                    + " layer"
            );
        }
    }

    /**
     * Validate pem store settings for transport of given type.
     * Throws an {@link org.opensearch.OpenSearchException} if:
     * - Either of the pem certificate or pem private key paths are not set.
     * - Client auth is set to REQUIRE but pem trusted certificates filepath is not set.
     * @param transportType transport type to validate
     * @param settings {@link org.opensearch.env.Environment} settings.
     */
    private void validatePemStoreSettings(CertType transportType, final Settings settings) throws OpenSearchException {
        final var transportSettings = settings.getByPrefix(transportType.sslSettingPrefix());
        final var clientAuth = ClientAuth.valueOf(
            transportSettings.get(CLIENT_AUTH_MODE, ClientAuth.OPTIONAL.name()).toUpperCase(Locale.ROOT)
        );
        if (!transportSettings.hasValue(PEM_CERT_FILEPATH) || !transportSettings.hasValue(PEM_KEY_FILEPATH)) {
            throw new OpenSearchException(
                "Wrong "
                    + transportType.certID().toLowerCase(Locale.ROOT)
                    + " SSL configuration. "
                    + String.join(", ", transportSettings.get(PEM_CERT_FILEPATH), transportSettings.get(PEM_KEY_FILEPATH))
                    + " must be set"
            );
        }
        if (clientAuth == ClientAuth.REQUIRE && !transportSettings.hasValue(PEM_TRUSTED_CAS_FILEPATH)) {
            throw new OpenSearchException(
                "Wrong "
                    + transportType.certID().toLowerCase(Locale.ROOT)
                    + " SSL configuration. "
                    + PEM_TRUSTED_CAS_FILEPATH
                    + " must be set if client auth is required"
            );
        }
    }

    /**
     * Validate key store settings for transport of given type.
     * Throws an {@link org.opensearch.OpenSearchException} if:
     * - Keystore filepath is not set.
     * - Client auth is set to REQUIRE but trust store filepath is not set.
     * @param transportType transport type to validate
     * @param settings {@link org.opensearch.env.Environment} settings.
     */
    private void validateKeyStoreSettings(CertType transportType, final Settings settings) throws OpenSearchException {
        final var transportSettings = settings.getByPrefix(transportType.sslSettingPrefix());
        final var clientAuth = ClientAuth.valueOf(
            transportSettings.get(CLIENT_AUTH_MODE, ClientAuth.OPTIONAL.name()).toUpperCase(Locale.ROOT)
        );
        if (!transportSettings.hasValue(KEYSTORE_FILEPATH)) {
            throw new OpenSearchException(
                "Wrong "
                    + transportType.certID().toLowerCase(Locale.ROOT)
                    + " SSL configuration. "
                    + transportSettings.get(KEYSTORE_FILEPATH)
                    + " must be set"
            );
        }
        if (clientAuth == ClientAuth.REQUIRE && !transportSettings.hasValue(TRUSTSTORE_FILEPATH)) {
            throw new OpenSearchException(
                "Wrong "
                    + transportType.certID().toLowerCase(Locale.ROOT)
                    + " SSL configuration. "
                    + TRUSTSTORE_FILEPATH
                    + " must be set if client auth is required"
            );
        }
    }

    private void validateTransportSettings(final Settings transportSettings) {
        if (!hasExtendedKeyUsageEnabled(transportSettings)) {
            if (hasPemStoreSettings(transportSettings)) {
                if (!transportSettings.hasValue(PEM_CERT_FILEPATH)
                    || !transportSettings.hasValue(PEM_KEY_FILEPATH)
                    || !transportSettings.hasValue(PEM_TRUSTED_CAS_FILEPATH)) {
                    throw new OpenSearchException(
                        "Wrong Transport SSL configuration. "
                            + String.join(
                                ",",
                                SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH,
                                SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH,
                                SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH
                            )
                            + " must be set"
                    );
                }

            } else if (hasKeyOrTrustStoreSettings(transportSettings)) {
                verifyKeyAndTrustStoreSettings(transportSettings);
            } else {
                throw new OpenSearchException(
                    "Wrong Transport SSL configuration. One of Keystore and Truststore files or X.509 PEM certificates and "
                        + "PKCS#8 keys groups should be set to configure Transport layer properly"
                );
            }
        } else {
            final var serverTransportSettings = transportSettings.getByPrefix(SSL_TRANSPORT_SERVER_EXTENDED_PREFIX);
            final var clientTransportSettings = transportSettings.getByPrefix(SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX);
            if (hasKeyOrTrustStoreSettings(transportSettings)) {
                verifyKeyAndTrustStoreSettings(transportSettings);
                if (!serverTransportSettings.hasValue(KEYSTORE_ALIAS)
                    || !serverTransportSettings.hasValue(TRUSTSTORE_ALIAS)
                    || !clientTransportSettings.hasValue(KEYSTORE_ALIAS)
                    || !clientTransportSettings.hasValue(TRUSTSTORE_ALIAS)) {
                    throw new OpenSearchException(
                        "Wrong Transport/Transport Client SSL configuration. "
                            + String.join(
                                ",",
                                SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS,
                                SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS,
                                SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS,
                                SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS
                            )
                            + " must be set if "
                            + SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED
                            + " is set"
                    );
                }
            } else if (!hasKeyOrTrustStoreSettings(transportSettings)) {
                if (!serverTransportSettings.hasValue(PEM_CERT_FILEPATH)
                    || !serverTransportSettings.hasValue(PEM_KEY_FILEPATH)
                    || !serverTransportSettings.hasValue(PEM_TRUSTED_CAS_FILEPATH)
                    || !clientTransportSettings.hasValue(PEM_CERT_FILEPATH)
                    || !clientTransportSettings.hasValue(PEM_KEY_FILEPATH)
                    || !clientTransportSettings.hasValue(PEM_TRUSTED_CAS_FILEPATH)) {
                    throw new OpenSearchException(
                        "Wrong Transport/Transport Client SSL configuration. "
                            + String.join(
                                ",",
                                SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH,
                                SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH,
                                SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH,
                                SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH,
                                SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH,
                                SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH
                            )
                            + " must be set if "
                            + SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED
                            + " is set"
                    );
                }
            } else {
                throw new OpenSearchException(
                    "Wrong Transport/Transport Client SSL configuration. One of Keystore and Truststore files or X.509 PEM certificates and "
                        + "PKCS#8 keys groups should be set to configure HTTP layer"
                );
            }
        }
    }

    private void verifyKeyAndTrustStoreSettings(final Settings settings) {
        if (!settings.hasValue(KEYSTORE_FILEPATH) || !settings.hasValue(TRUSTSTORE_FILEPATH)) {
            throw new OpenSearchException(
                "Wrong Transport/Tran SSL configuration. One of Keystore and Truststore files or X.509 PEM certificates and "
                    + "PKCS#8 keys groups should be set to configure Transport layer properly"
            );
        }
    }

    private boolean hasExtendedKeyUsageEnabled(final Settings settings) {
        return settings.getAsBoolean(EXTENDED_KEY_USAGE_ENABLED, SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED_DEFAULT);
    }

    private boolean hasKeyOrTrustStoreSettings(final Settings settings) {
        return settings.hasValue(KEYSTORE_FILEPATH) || settings.hasValue(TRUSTSTORE_FILEPATH);
    }

    private boolean hasPemStoreSettings(final Settings settings) {
        return settings.hasValue(PEM_KEY_FILEPATH) || settings.hasValue(PEM_CERT_FILEPATH) || settings.hasValue(PEM_TRUSTED_CAS_FILEPATH);
    }

    void jceWarnings() {
        try {
            final int aesMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");

            if (aesMaxKeyLength < 256) {
                // CS-SUPPRESS-SINGLE: RegexpSingleline Java Cryptography Extension is unrelated to OpenSearch extensions
                LOGGER.info(
                    "AES-256 not supported, max key length for AES is {} bit."
                        + " (This is not an issue, it just limits possible encryption strength. "
                        + "To enable AES 256, "
                        + "install 'Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files')",
                    aesMaxKeyLength
                );
                // CS-ENFORCE-SINGLE
            }
        } catch (final NoSuchAlgorithmException e) {
            LOGGER.error("AES encryption not supported (SG 1). ", e);
        }
    }
}
