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
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

import io.netty.handler.codec.http2.Http2SecurityUtil;
import org.opensearch.OpenSearchException;
import org.opensearch.security.ssl.config.Certificate;
import org.opensearch.security.ssl.config.KeyStoreConfiguration;
import org.opensearch.security.ssl.config.SslParameters;
import org.opensearch.security.ssl.config.TrustStoreConfiguration;

public class SslConfiguration {

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

    // TODO we always add all HTTP 2 ciphers, while maybe it is better to set them differently
    public String[] ciphers () {
        return Stream.concat(
                Http2SecurityUtil.CIPHERS.stream(),
                sslParameters.allowedCiphers().stream()
        ).distinct().toArray(String[]::new);
    }

    public String[] allowedProtocols () {
        return sslParameters.allowedProtocols().toArray(new String[0]);
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

    @SuppressWarnings("removal")
    SSLContext buildSSLContext(final boolean validateCertificates, boolean isClient) {
        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<SSLContext>) () -> {
                Set<X500Principal> issuerDns = keyStoreConfiguration.getIssuerDns();
                KeyManagerFactory kmFactory = keyStoreConfiguration.createKeyManagerFactory(validateCertificates);
                TrustManagerFactory tmFactory = trustStoreConfiguration.createTrustManagerFactory(validateCertificates, issuerDns);
                SSLContext sslContext = SSLContext.getInstance("TLS", sslParameters.provider());
                sslContext.init(kmFactory.getKeyManagers(), tmFactory.getTrustManagers(), null);

                SSLSessionContext serverSessionContext;
                if (!isClient) {
                    serverSessionContext = sslContext.getServerSessionContext();
                } else {
                    serverSessionContext = sslContext.getClientSessionContext();
                }
                serverSessionContext.setSessionCacheSize(0);
                serverSessionContext.setSessionTimeout(0);

                return sslContext;
            });
        } catch (PrivilegedActionException e) {
            throw new OpenSearchException("Failed to build server SSL context", e);
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
