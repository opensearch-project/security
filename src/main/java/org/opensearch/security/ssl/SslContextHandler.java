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

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.SSLEngine;

import org.opensearch.security.ssl.config.Certificate;
import org.opensearch.transport.NettyAllocator;

import io.netty.handler.ssl.SslContext;

public class SslContextHandler {

    private SslContext sslContext;

    private final SslConfiguration sslConfiguration;

    private final List<Certificate> loadedCertificates;

    public SslContextHandler(final SslConfiguration sslConfiguration) {
        this(sslConfiguration, false);
    }

    public SslContextHandler(final SslConfiguration sslConfiguration, final boolean client) {
        this.sslContext = client ? sslConfiguration.buildClientSslContext(true) : sslConfiguration.buildServerSslContext(true);
        this.sslConfiguration = sslConfiguration;
        this.loadedCertificates = sslConfiguration.certificates();
    }

    public SSLEngine createSSLEngine() {
        return sslContext.newEngine(NettyAllocator.getAllocator());
    }

    public SSLEngine createSSLEngine(final String hostname, final int port) {
        return sslContext.newEngine(NettyAllocator.getAllocator(), hostname, port);
    }

    public SslConfiguration sslConfiguration() {
        return sslConfiguration;
    }

    SslContext sslContext() {
        return sslContext;
    }

    public Stream<Certificate> keyMaterialCertificates() {
        return keyMaterialCertificates(loadedCertificates);
    }

    Stream<Certificate> keyMaterialCertificates(final List<Certificate> certificates) {
        return certificates.stream().filter(Certificate::hasKey);
    }

    void reloadSslContext() throws CertificateException {
        final var newCertificates = sslConfiguration.certificates();

        if (sameCertificates(newCertificates)) {
            return;
        }
        validateNewCertificates(newCertificates);
        invalidateSessions();
        if (sslContext.isClient()) {
            sslContext = sslConfiguration.buildClientSslContext(false);
        } else {
            sslContext = sslConfiguration.buildServerSslContext(false);
        }
        loadedCertificates.clear();
        loadedCertificates.addAll(newCertificates);
    }

    private boolean sameCertificates(final List<Certificate> newCertificates) {
        final Set<String> currentCertSignatureSet = keyMaterialCertificates().map(Certificate::x509Certificate)
            .map(X509Certificate::getSignature)
            .map(s -> new String(s, StandardCharsets.UTF_8))
            .collect(Collectors.toSet());
        final Set<String> newCertSignatureSet = keyMaterialCertificates(newCertificates).map(Certificate::x509Certificate)
            .map(X509Certificate::getSignature)
            .map(s -> new String(s, StandardCharsets.UTF_8))
            .collect(Collectors.toSet());
        return currentCertSignatureSet.equals(newCertSignatureSet);
    }

    private void validateSubjectDns(final List<Certificate> newCertificates) throws CertificateException {
        final List<String> currentSubjectDNs = keyMaterialCertificates().map(Certificate::subject).sorted().collect(Collectors.toList());
        final List<String> newSubjectDNs = keyMaterialCertificates(newCertificates).map(Certificate::subject)
            .sorted()
            .collect(Collectors.toList());
        if (!currentSubjectDNs.equals(newSubjectDNs)) {
            throw new CertificateException(
                "New certificates do not have valid Subject DNs. Current Subject DNs "
                    + currentSubjectDNs
                    + " new Subject DNs "
                    + newSubjectDNs
            );
        }
    }

    private void validateIssuerDns(final List<Certificate> newCertificates) throws CertificateException {
        final List<String> currentIssuerDNs = keyMaterialCertificates().map(Certificate::issuer).sorted().collect(Collectors.toList());
        final List<String> newIssuerDNs = keyMaterialCertificates(newCertificates).map(Certificate::issuer)
            .sorted()
            .collect(Collectors.toList());
        if (!currentIssuerDNs.equals(newIssuerDNs)) {
            throw new CertificateException(
                "New certificates do not have valid Issuer DNs. Current Issuer DNs: "
                    + currentIssuerDNs
                    + " new Issuer DNs: "
                    + newIssuerDNs
            );
        }
    }

    private void validateSans(final List<Certificate> newCertificates) throws CertificateException {
        final List<String> currentSans = keyMaterialCertificates().map(Certificate::subjectAlternativeNames)
            .sorted()
            .collect(Collectors.toList());
        final List<String> newSans = keyMaterialCertificates(newCertificates).map(Certificate::subjectAlternativeNames)
            .sorted()
            .collect(Collectors.toList());
        if (!currentSans.equals(newSans)) {
            throw new CertificateException(
                "New certificates do not have valid SANs. Current SANs: " + currentSans + " new SANs: " + newSans
            );
        }
    }

    private void validateNewCertificates(final List<Certificate> newCertificates) throws CertificateException {
        for (final var certificate : newCertificates) {
            certificate.x509Certificate().checkValidity();
        }
        validateSubjectDns(newCertificates);
        validateIssuerDns(newCertificates);
        validateSans(newCertificates);
    }

    private void invalidateSessions() {
        final var sessionContext = sslContext.sessionContext();
        if (sessionContext != null) {
            for (final var sessionId : Collections.list(sessionContext.getIds())) {
                final var session = sessionContext.getSession(sessionId);
                if (session != null) {
                    session.invalidate();
                }
            }
        }
    }

}
