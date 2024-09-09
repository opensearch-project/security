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
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
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

    public SslParameters sslParameters() {
        return sslParameters;
    }

    @SuppressWarnings("removal")
    SslContext buildServerSslContext(final boolean validateCertificates) {
        try {
            return AccessController.doPrivileged(
                (PrivilegedExceptionAction<SslContext>) () -> SslContextBuilder.forServer(
                    keyStoreConfiguration.createKeyManagerFactory(validateCertificates)
                )
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
                    .trustManager(trustStoreConfiguration.createTrustManagerFactory(validateCertificates))
                    .build()
            );
        } catch (PrivilegedActionException e) {
            throw new OpenSearchException("Filed to build server SSL context", e);
        }
    }

    @SuppressWarnings("removal")
    SslContext buildClientSslContext(final boolean validateCertificates) {
        try {
            return AccessController.doPrivileged(
                (PrivilegedExceptionAction<SslContext>) () -> SslContextBuilder.forClient()
                    .sslProvider(sslParameters.provider())
                    .protocols(sslParameters.allowedProtocols())
                    .ciphers(sslParameters.allowedCiphers())
                    .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
                    .sessionCacheSize(0)
                    .sessionTimeout(0)
                    .sslProvider(sslParameters.provider())
                    .keyManager(keyStoreConfiguration.createKeyManagerFactory(validateCertificates))
                    .trustManager(trustStoreConfiguration.createTrustManagerFactory(validateCertificates))
                    .build()
            );
        } catch (PrivilegedActionException e) {
            throw new OpenSearchException("Filed to build client SSL context", e);
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
