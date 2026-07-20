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

import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.security.ssl.config.Certificate;
import org.opensearch.security.ssl.config.KeyStoreConfiguration;
import org.opensearch.security.ssl.config.SslParameters;
import org.opensearch.security.ssl.config.TrustStoreConfiguration;

import io.netty.handler.codec.http2.Http2SecurityUtil;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;

public class SslConfiguration {

    private final static Logger LOGGER = LogManager.getLogger(SslConfiguration.class);

    private final SslParameters sslParameters;

    private final TrustStoreConfiguration trustStoreConfiguration;

    private final KeyStoreConfiguration keyStoreConfiguration;

    public SslConfiguration(
        final SslParameters sslParameters,
        final TrustStoreConfiguration trustStoreConfiguration,
        final KeyStoreConfiguration keyStoreConfiguration
    ) {
        this.sslParameters = sslParameters;
        this.trustStoreConfiguration = trustStoreConfiguration;
        this.keyStoreConfiguration = keyStoreConfiguration;
    }

    public List<Path> dependentFiles() {
        return Stream.concat(keyStoreConfiguration.files().stream(), Stream.of(trustStoreConfiguration.file()))
            .collect(Collectors.toList());
    }

    public List<Certificate> certificates() {
        return Stream.concat(trustStoreConfiguration.loadCertificates().stream(), keyStoreConfiguration.loadCertificates().stream())
            .collect(Collectors.toList());
    }

    public KeyManagerFactory keyStoreFactory() {
        return keyStoreConfiguration.createKeyManagerFactory(sslParameters.shouldValidateNewCertDNs());
    }

    public TrustManagerFactory trustStoreFactory() {
        return trustStoreConfiguration.createTrustManagerFactory(
            sslParameters.shouldValidateNewCertDNs(),
            keyStoreConfiguration.getIssuerDns()
        );
    }

    public SslParameters sslParameters() {
        return sslParameters;
    }

    SslContext buildServerSslContext(final boolean validateCertificates) {
        try {
            return AccessController.doPrivilegedChecked(() -> {
                KeyManagerFactory kmFactory = keyStoreConfiguration.createKeyManagerFactory(validateCertificates);
                Set<X500Principal> issuerDns = keyStoreConfiguration.getIssuerDns();
                final SslContextBuilder builder = SslContextBuilder.forServer(kmFactory)
                    .sslProvider(sslParameters.provider())
                    .clientAuth(sslParameters.clientAuth())
                    .protocols(sslParameters.allowedProtocols().toArray(new String[0]))
                    // TODO we always add all HTTP 2 ciphers, while maybe it is better to set them differently
                    .ciphers(
                        Stream.concat(
                            Http2SecurityUtil.CIPHERS.stream(),
                            StreamSupport.stream(sslParameters.allowedCiphers().spliterator(), false)
                        ).collect(Collectors.toSet()),
                        SupportedCipherSuiteFilter.INSTANCE
                    )
                    .sessionCacheSize(0)
                    .sessionTimeout(0)
                    .applicationProtocolConfig(
                        new ApplicationProtocolConfig(
                            ApplicationProtocolConfig.Protocol.ALPN,
                            // NO_ADVERTISE is currently the only mode supported by both OpenSsl and JDK providers.
                            ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                            // ACCEPT is currently the only mode supported by both OpenSsl and JDK providers.
                            ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                            ApplicationProtocolNames.HTTP_2,
                            ApplicationProtocolNames.HTTP_1_1
                        )
                    )
                    .trustManager(trustStoreConfiguration.createTrustManagerFactory(validateCertificates, issuerDns));
                routePkcs11ThroughSunJsse(builder);
                return builder.build();
            });
        } catch (SSLException e) {
            throw new OpenSearchException("Failed to build server SSL context", e);
        }
    }

    /**
     * A PKCS#11-resident private key is non-exportable, so the BouncyCastle FIPS JSSE provider cannot sign
     * with it (it fails with "no encoding for key" during the TLS CertificateVerify). SunJSSE instead
     * delegates the signature operation to the key's own provider (SunPKCS11), letting the token perform it.
     * This only affects the TLS engine's handshake signing; the JDK {@link io.netty.handler.ssl.SslProvider} is unchanged.
     */
    private void routePkcs11ThroughSunJsse(final SslContextBuilder builder) {
        if (!keyStoreConfiguration.isPkcs11()) {
            return;
        }
        final Provider sunJSSE = Security.getProvider("SunJSSE");
        if (sunJSSE == null) {
            throw new OpenSearchException("SunJSSE provider not available; required for PKCS#11 key store support");
        }
        builder.sslContextProvider(sunJSSE);
    }

    SslContext buildClientSslContext(final boolean validateCertificates) {
        try {
            return AccessController.doPrivilegedChecked(() -> {
                KeyManagerFactory kmFactory = keyStoreConfiguration.createKeyManagerFactory(validateCertificates);
                Set<X500Principal> issuerDns = keyStoreConfiguration.getIssuerDns();
                final SslContextBuilder builder = SslContextBuilder.forClient()
                    .sslProvider(sslParameters.provider())
                    .protocols(sslParameters.allowedProtocols())
                    .ciphers(sslParameters.allowedCiphers())
                    .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
                    .sessionCacheSize(0)
                    .sessionTimeout(0)
                    .sslProvider(sslParameters.provider())
                    .keyManager(kmFactory)
                    .trustManager(trustStoreConfiguration.createTrustManagerFactory(validateCertificates, issuerDns))
                    .endpointIdentificationAlgorithm(null);
                routePkcs11ThroughSunJsse(builder);
                return builder.build();
            });
        } catch (Exception e) {
            throw new OpenSearchException("Failed to build client SSL context", e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SslConfiguration that = (SslConfiguration) o;
        return Objects.equals(sslParameters, that.sslParameters)
            && Objects.equals(trustStoreConfiguration, that.trustStoreConfiguration)
            && Objects.equals(keyStoreConfiguration, that.keyStoreConfiguration);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sslParameters, trustStoreConfiguration, keyStoreConfiguration);
    }
}
