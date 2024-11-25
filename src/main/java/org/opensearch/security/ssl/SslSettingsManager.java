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
import org.opensearch.common.Booleans;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.security.ssl.config.CertType;
import org.opensearch.security.ssl.config.SslCertificatesLoader;
import org.opensearch.security.ssl.config.SslParameters;
import org.opensearch.watcher.FileChangesListener;
import org.opensearch.watcher.FileWatcher;
import org.opensearch.watcher.ResourceWatcherService;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.OpenSsl;
import io.netty.util.internal.PlatformDependent;

import static org.opensearch.security.ssl.util.SSLConfigConstants.CLIENT_AUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.EXTENDED_KEY_USAGE_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.KEYSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.KEYSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_CERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_KEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.PEM_TRUSTED_CAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_DEFAULT;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE;
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

    public Optional<SslContextHandler> sslContextHandler(final CertType sslConfigPrefix) {
        return Optional.ofNullable(sslSettingsContexts.get(sslConfigPrefix));
    }

    private Map<CertType, SslContextHandler> buildSslContexts(final Environment environment) {
        final var contexts = new ImmutableMap.Builder<CertType, SslContextHandler>();
        final var configurations = loadConfigurations(environment);
        Optional.ofNullable(configurations.get(CertType.HTTP))
            .ifPresentOrElse(
                sslConfiguration -> contexts.put(CertType.HTTP, new SslContextHandler(sslConfiguration)),
                () -> LOGGER.warn("SSL Configuration for HTTP Layer hasn't been set")
            );
        Optional.ofNullable(configurations.get(CertType.TRANSPORT)).ifPresentOrElse(sslConfiguration -> {
            contexts.put(CertType.TRANSPORT, new SslContextHandler(sslConfiguration));
            final var transportClientConfiguration = Optional.ofNullable(configurations.get(CertType.TRANSPORT_CLIENT))
                .orElse(sslConfiguration);
            contexts.put(CertType.TRANSPORT_CLIENT, new SslContextHandler(transportClientConfiguration, true));
        }, () -> LOGGER.warn("SSL Configuration for Transport Layer hasn't been set"));
        return contexts.build();
    }

    public synchronized void reloadSslContext(final CertType certType) {
        sslContextHandler(certType).ifPresentOrElse(sscContextHandler -> {
            try {
                if (sscContextHandler.reloadSslContext()) {
                    LOGGER.info("{} SSL context reloaded", certType.name());
                }
            } catch (CertificateException e) {
                throw new OpenSearchException(e);
            }
        }, () -> LOGGER.error("Missing SSL Context for {}", certType.name()));
    }

    private Map<CertType, SslConfiguration> loadConfigurations(final Environment environment) {
        final var settings = environment.settings();
        final var httpSettings = settings.getByPrefix(CertType.HTTP.sslConfigPrefix());
        final var transpotSettings = settings.getByPrefix(CertType.TRANSPORT.sslConfigPrefix());
        if (httpSettings.isEmpty() && transpotSettings.isEmpty()) {
            throw new OpenSearchException("No SSL configuration found");
        }
        jceWarnings();
        openSslWarnings(settings);

        final var httpEnabled = httpSettings.getAsBoolean(ENABLED, SECURITY_SSL_HTTP_ENABLED_DEFAULT);
        final var transportEnabled = transpotSettings.getAsBoolean(ENABLED, SECURITY_SSL_TRANSPORT_ENABLED_DEFAULT);

        final var configurationBuilder = ImmutableMap.<CertType, SslConfiguration>builder();
        if (httpEnabled && !clientNode(settings)) {
            validateHttpSettings(httpSettings);
            final var httpSslParameters = SslParameters.loader(httpSettings).load(true);
            final var httpTrustAndKeyStore = new SslCertificatesLoader(CertType.HTTP.sslConfigPrefix()).loadConfiguration(environment);
            configurationBuilder.put(
                CertType.HTTP,
                new SslConfiguration(httpSslParameters, httpTrustAndKeyStore.v1(), httpTrustAndKeyStore.v2())
            );
            LOGGER.info("TLS HTTP Provider                    : {}", httpSslParameters.provider());
            LOGGER.info("Enabled TLS protocols for HTTP layer : {}", httpSslParameters.allowedProtocols());
        }
        final var transportSslParameters = SslParameters.loader(transpotSettings).load(false);
        if (transportEnabled) {
            if (hasExtendedKeyUsageEnabled(transpotSettings)) {
                validateTransportSettings(transpotSettings);
                final var transportServerTrustAndKeyStore = new SslCertificatesLoader(
                    CertType.TRANSPORT.sslConfigPrefix(),
                    SSL_TRANSPORT_SERVER_EXTENDED_PREFIX
                ).loadConfiguration(environment);
                configurationBuilder.put(
                    CertType.TRANSPORT,
                    new SslConfiguration(transportSslParameters, transportServerTrustAndKeyStore.v1(), transportServerTrustAndKeyStore.v2())
                );
                final var transportClientTrustAndKeyStore = new SslCertificatesLoader(
                    CertType.TRANSPORT.sslConfigPrefix(),
                    SSL_TRANSPORT_CLIENT_EXTENDED_PREFIX
                ).loadConfiguration(environment);
                configurationBuilder.put(
                    CertType.TRANSPORT_CLIENT,
                    new SslConfiguration(transportSslParameters, transportClientTrustAndKeyStore.v1(), transportClientTrustAndKeyStore.v2())
                );
            } else {
                validateTransportSettings(transpotSettings);
                final var transportTrustAndKeyStore = new SslCertificatesLoader(CertType.TRANSPORT.sslConfigPrefix()).loadConfiguration(
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

    private void validateHttpSettings(final Settings httpSettings) {
        if (httpSettings == null) return;
        if (!httpSettings.getAsBoolean(ENABLED, SECURITY_SSL_HTTP_ENABLED_DEFAULT)) return;

        final var clientAuth = ClientAuth.valueOf(httpSettings.get(CLIENT_AUTH_MODE, ClientAuth.OPTIONAL.name()).toUpperCase(Locale.ROOT));

        if (hasPemStoreSettings(httpSettings)) {
            if (!httpSettings.hasValue(PEM_CERT_FILEPATH) || !httpSettings.hasValue(PEM_KEY_FILEPATH)) {
                throw new OpenSearchException(
                    "Wrong HTTP SSL configuration. "
                        + String.join(", ", SECURITY_SSL_HTTP_PEMCERT_FILEPATH, SECURITY_SSL_HTTP_PEMKEY_FILEPATH)
                        + " must be set"
                );
            }
            if (clientAuth == ClientAuth.REQUIRE && !httpSettings.hasValue(PEM_TRUSTED_CAS_FILEPATH)) {
                throw new OpenSearchException(
                    "Wrong HTTP SSL configuration. " + SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH + " must be set if client auth is required"
                );
            }
        } else if (hasKeyOrTrustStoreSettings(httpSettings)) {
            if (!httpSettings.hasValue(KEYSTORE_FILEPATH)) {
                throw new OpenSearchException("Wrong HTTP SSL configuration. " + SECURITY_SSL_HTTP_KEYSTORE_FILEPATH + " must be set");
            }
            if (clientAuth == ClientAuth.REQUIRE && !httpSettings.hasValue(TRUSTSTORE_FILEPATH)) {
                throw new OpenSearchException(
                    "Wrong HTTP SSL configuration. " + SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH + " must be set if client auth is required"
                );
            }
        } else {
            throw new OpenSearchException(
                "Wrong HTTP SSL configuration. One of Keystore and Truststore files or X.509 PEM certificates and "
                    + "PKCS#8 keys groups should be set to configure HTTP layer"
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

    void openSslWarnings(final Settings settings) {
        if (!OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED
            && OpenSsl.isAvailable()
            && (settings.getAsBoolean(SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, true)
                || settings.getAsBoolean(SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, true))) {
            if (PlatformDependent.javaVersion() < 12) {
                LOGGER.warn(
                    "Support for OpenSSL with Java 11 or prior versions require using Netty allocator. Set "
                        + "'opensearch.unsafe.use_netty_default_allocator' system property to true"
                );
            } else {
                LOGGER.warn("Support for OpenSSL with Java 12+ has been removed from OpenSearch Security. Using JDK SSL instead.");
            }
        }
        if (OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable()) {
            LOGGER.info("OpenSSL {} ({}) available", OpenSsl.versionString(), OpenSsl.version());

            if (OpenSsl.version() < 0x10002000L) {
                LOGGER.warn(
                    "Outdated OpenSSL version detected. You should update to 1.0.2k or later. Currently installed: {}",
                    OpenSsl.versionString()
                );
            }

            if (!OpenSsl.supportsHostnameValidation()) {
                LOGGER.warn(
                    "Your OpenSSL version {} does not support hostname verification. You should update to 1.0.2k or later.",
                    OpenSsl.versionString()
                );
            }

            LOGGER.debug("OpenSSL available ciphers {}", OpenSsl.availableOpenSslCipherSuites());
        } else {
            boolean openSslIsEnabled = false;

            if (settings.hasValue(SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE) == true) {
                openSslIsEnabled |= Booleans.parseBoolean(settings.get(SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE));
            }

            if (settings.hasValue(SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE) == true) {
                openSslIsEnabled |= Booleans.parseBoolean(settings.get(SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE));
            }

            if (openSslIsEnabled == true) {
                /* only print warning if OpenSsl is enabled explicitly but not available */
                LOGGER.warn(
                    "OpenSSL not available (this is not an error, we simply fallback to built-in JDK SSL) because of ",
                    OpenSsl.unavailabilityCause()
                );
            }
        }
    }

}
