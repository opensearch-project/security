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

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.SSLContext;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslProvider;

import static org.opensearch.security.ssl.util.SSLConfigConstants.ALLOWED_OPENSSL_HTTP_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ALLOWED_OPENSSL_HTTP_PROTOCOLS_PRIOR_OPENSSL_1_1_1_BETA_9;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ALLOWED_OPENSSL_TRANSPORT_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ALLOWED_OPENSSL_TRANSPORT_PROTOCOLS_PRIOR_OPENSSL_1_1_1_BETA_9;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ALLOWED_SSL_CIPHERS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ALLOWED_SSL_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.CLIENT_AUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED_CIPHERS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLE_OPENSSL_IF_AVAILABLE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.OPENSSL_1_1_1_BETA_9;
import static org.opensearch.security.ssl.util.SSLConfigConstants.OPENSSL_AVAILABLE;

public class SslParameters {

    private final SslProvider provider;

    private final ClientAuth clientAuth;

    private final List<String> protocols;

    private final List<String> ciphers;

    private SslParameters(SslProvider provider, final ClientAuth clientAuth, List<String> protocols, List<String> ciphers) {
        this.provider = provider;
        this.ciphers = ciphers;
        this.protocols = protocols;
        this.clientAuth = clientAuth;
    }

    public ClientAuth clientAuth() {
        return clientAuth;
    }

    public SslProvider provider() {
        return provider;
    }

    public List<String> allowedCiphers() {
        return ciphers;
    }

    public List<String> allowedProtocols() {
        return protocols;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SslParameters that = (SslParameters) o;
        return provider == that.provider && Objects.equals(ciphers, that.ciphers) && Objects.equals(protocols, that.protocols);
    }

    @Override
    public int hashCode() {
        return Objects.hash(provider, ciphers, protocols);
    }

    public static Loader loader(final Settings sslConfigSettings) {
        return new Loader(sslConfigSettings);
    }

    public static final class Loader {

        private final static Logger LOGGER = LogManager.getLogger(SslParameters.class);

        private final Settings sslConfigSettings;

        public Loader(final Settings sslConfigSettings) {
            this.sslConfigSettings = sslConfigSettings;
        }

        private SslProvider provider(final Settings settings) {
            final var useOpenSslIfAvailable = settings.getAsBoolean(ENABLE_OPENSSL_IF_AVAILABLE, true);
            if (OPENSSL_AVAILABLE && useOpenSslIfAvailable) {
                return SslProvider.OPENSSL;
            } else {
                return SslProvider.JDK;
            }
        }

        private List<String> protocols(final SslProvider provider, final Settings settings, boolean http) {
            final var allowedProtocols = settings.getAsList(ENABLED_PROTOCOLS, List.of(ALLOWED_SSL_PROTOCOLS));
            if (provider == SslProvider.OPENSSL) {
                final String[] supportedProtocols;
                if (OpenSsl.version() > OPENSSL_1_1_1_BETA_9) {
                    supportedProtocols = http ? ALLOWED_OPENSSL_HTTP_PROTOCOLS : ALLOWED_OPENSSL_TRANSPORT_PROTOCOLS;
                } else {
                    supportedProtocols = http
                        ? ALLOWED_OPENSSL_HTTP_PROTOCOLS_PRIOR_OPENSSL_1_1_1_BETA_9
                        : ALLOWED_OPENSSL_TRANSPORT_PROTOCOLS_PRIOR_OPENSSL_1_1_1_BETA_9;
                }
                return openSslProtocols(allowedProtocols, supportedProtocols);
            } else {
                return jdkProtocols(allowedProtocols);
            }
        }

        private List<String> openSslProtocols(final List<String> allowedSslProtocols, final String... supportedProtocols) {
            LOGGER.debug("OpenSSL supports the following {} protocols {}", supportedProtocols.length, supportedProtocols);
            return Stream.of(supportedProtocols).filter(allowedSslProtocols::contains).collect(Collectors.toList());
        }

        private List<String> jdkProtocols(final List<String> allowedSslProtocols) {
            try {
                final var supportedProtocols = SSLContext.getDefault().getDefaultSSLParameters().getProtocols();
                LOGGER.debug("JVM supports the following {} protocols {}", supportedProtocols.length, supportedProtocols);
                return Stream.of(supportedProtocols).filter(allowedSslProtocols::contains).collect(Collectors.toList());
            } catch (final NoSuchAlgorithmException e) {
                throw new OpenSearchException("Unable to determine supported protocols", e);
            }
        }

        private List<String> ciphers(final SslProvider provider, final Settings settings) {
            final var allowed = settings.getAsList(ENABLED_CIPHERS, List.of(ALLOWED_SSL_CIPHERS));
            final Stream<String> allowedCiphers;
            if (provider == SslProvider.OPENSSL) {
                LOGGER.debug(
                    "OpenSSL {} supports the following ciphers (java-style) {}",
                    OpenSsl.versionString(),
                    OpenSsl.availableJavaCipherSuites()
                );
                LOGGER.debug(
                    "OpenSSL {} supports the following ciphers (openssl-style) {}",
                    OpenSsl.versionString(),
                    OpenSsl.availableOpenSslCipherSuites()
                );
                allowedCiphers = allowed.stream().filter(OpenSsl::isCipherSuiteAvailable);
            } else {
                try {
                    final var supportedCiphers = SSLContext.getDefault().getDefaultSSLParameters().getCipherSuites();
                    LOGGER.debug("JVM supports the following {} ciphers {}", supportedCiphers.length, supportedCiphers);
                    allowedCiphers = Stream.of(supportedCiphers).filter(allowed::contains);
                } catch (final NoSuchAlgorithmException e) {
                    throw new OpenSearchException("Unable to determine ciphers protocols", e);
                }
            }
            return allowedCiphers.sorted(String::compareTo).collect(Collectors.toList());
        }

        public SslParameters load(final boolean http) {
            final var clientAuth = http
                ? ClientAuth.valueOf(sslConfigSettings.get(CLIENT_AUTH_MODE, ClientAuth.OPTIONAL.name()).toUpperCase(Locale.ROOT))
                : ClientAuth.REQUIRE;

            final var provider = provider(sslConfigSettings);
            final var sslParameters = new SslParameters(
                provider,
                clientAuth,
                protocols(provider, sslConfigSettings, http),
                ciphers(provider, sslConfigSettings)
            );
            if (sslParameters.allowedProtocols().isEmpty()) {
                throw new OpenSearchSecurityException("No ssl protocols for " + (http ? "HTTP" : "Transport") + " layer");
            }
            if (sslParameters.allowedCiphers().isEmpty()) {
                throw new OpenSearchSecurityException("No valid cipher suites for " + (http ? "HTTP" : "Transport") + " layer");
            }
            return sslParameters;
        }

    }

}
