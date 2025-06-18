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
import java.security.Provider;
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
import io.netty.handler.ssl.SslProvider;

import static org.opensearch.security.ssl.util.SSLConfigConstants.ALLOWED_SSL_CIPHERS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ALLOWED_SSL_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.CLIENT_AUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED_CIPHERS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENABLED_PROTOCOLS;
import static org.opensearch.security.ssl.util.SSLConfigConstants.ENFORCE_CERT_RELOAD_DN_VERIFICATION;

public class SslParameters {

    private final SslProvider provider;

    private final ClientAuth clientAuth;

    private final List<String> protocols;

    private final List<String> ciphers;

    private final boolean validateCertDNsOnReload;

    private SslParameters(
        SslProvider provider,
        final ClientAuth clientAuth,
        List<String> protocols,
        List<String> ciphers,
        boolean validateCertDNsOnReload
    ) {
        this.provider = provider;
        this.ciphers = ciphers;
        this.protocols = protocols;
        this.clientAuth = clientAuth;
        this.validateCertDNsOnReload = validateCertDNsOnReload;
    }

    public ClientAuth clientAuth() {
        return clientAuth;
    }

    public SslProvider provider() {
        return provider;
    }

//    public Provider provider(){
//        switch (provider) {
//            case SslProvider.JDK:
//                break;
//            case SslProvider.OPENSSL:
//                break;
//            case SslProvider.OPENSSL_REFCNT:
//                break;
//            default:
//                throw new IllegalStateException("Unexpected value: " + provider);
//        }
//    }

    public List<String> allowedCiphers() {
        return ciphers;
    }

    public List<String> allowedProtocols() {
        return protocols;
    }

    public boolean shouldValidateNewCertDNs() {
        return validateCertDNsOnReload;
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
            return SslProvider.JDK;
        }

        private boolean validateCertDNsOnReload(final Settings settings) {
            return settings.getAsBoolean(ENFORCE_CERT_RELOAD_DN_VERIFICATION, true);
        }

        private List<String> protocols(final SslProvider provider, final Settings settings, boolean http) {
            final var allowedProtocols = settings.getAsList(ENABLED_PROTOCOLS, List.of(ALLOWED_SSL_PROTOCOLS));
            return jdkProtocols(allowedProtocols);
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
            try {
                final var supportedCiphers = SSLContext.getDefault().getDefaultSSLParameters().getCipherSuites();
                LOGGER.debug("JVM supports the following {} ciphers {}", supportedCiphers.length, supportedCiphers);
                allowedCiphers = Stream.of(supportedCiphers).filter(allowed::contains);
            } catch (final NoSuchAlgorithmException e) {
                throw new OpenSearchException("Unable to determine ciphers protocols", e);
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
                ciphers(provider, sslConfigSettings),
                validateCertDNsOnReload(sslConfigSettings)
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
