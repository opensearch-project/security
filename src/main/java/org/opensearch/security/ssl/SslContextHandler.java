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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.ssl.config.Certificate;
import org.opensearch.transport.NettyAllocator;

import io.netty.handler.ssl.SslContext;

import static java.util.function.Predicate.not;

public class SslContextHandler {

    private final static Logger LOGGER = LogManager.getLogger(SslContextHandler.class);

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

    public Stream<Certificate> authorityCertificates() {
        return authorityCertificates(loadedCertificates);
    }

    Stream<Certificate> authorityCertificates(final List<Certificate> certificates) {
        return certificates.stream().filter(not(Certificate::hasKey));
    }

    public Stream<Certificate> keyMaterialCertificates() {
        return keyMaterialCertificates(loadedCertificates);
    }

    Stream<Certificate> keyMaterialCertificates(final List<Certificate> certificates) {
        return certificates.stream().filter(Certificate::hasKey);
    }

    boolean reloadSslContext() throws CertificateException {
        final var newCertificates = sslConfiguration.certificates();

        boolean hasChanges = false;

        final var loadedAuthorityCertificates = authorityCertificates().collect(Collectors.toList());
        final var loadedKeyMaterialCertificates = keyMaterialCertificates().collect(Collectors.toList());
        final var newAuthorityCertificates = authorityCertificates(newCertificates).collect(Collectors.toList());
        final var newKeyMaterialCertificates = keyMaterialCertificates(newCertificates).collect(Collectors.toList());

        if (notSameCertificates(loadedAuthorityCertificates, newAuthorityCertificates)) {
            LOGGER.debug("Certification authority has changed");
            hasChanges = true;
            validateDates(newAuthorityCertificates);
        }

        if (notSameCertificates(loadedKeyMaterialCertificates, newKeyMaterialCertificates)) {
            LOGGER.debug("Key material and access certificate has changed");
            hasChanges = true;
            validateNewKeyMaterialCertificates(
                loadedKeyMaterialCertificates,
                newKeyMaterialCertificates,
                sslConfiguration.sslParameters().shouldValidateNewCertDNs()
            );
        }
        if (hasChanges) {
            invalidateSessions();
            if (sslContext.isClient()) {
                sslContext = sslConfiguration.buildClientSslContext(false);
            } else {
                sslContext = sslConfiguration.buildServerSslContext(false);
            }
            loadedCertificates.clear();
            loadedCertificates.addAll(newCertificates);
        }
        return hasChanges;
    }

    private boolean notSameCertificates(final List<Certificate> loadedCertificates, final List<Certificate> newCertificates) {
        final Set<String> currentCertSignatureSet = loadedCertificates.stream()
            .map(Certificate::x509Certificate)
            .map(X509Certificate::getSignature)
            .map(s -> new String(s, StandardCharsets.UTF_8))
            .collect(Collectors.toSet());
        final Set<String> newCertSignatureSet = newCertificates.stream()
            .map(Certificate::x509Certificate)
            .map(X509Certificate::getSignature)
            .map(s -> new String(s, StandardCharsets.UTF_8))
            .collect(Collectors.toSet());
        return !currentCertSignatureSet.equals(newCertSignatureSet);
    }

    private void validateDates(final List<Certificate> newCertificates) throws CertificateException {
        for (final var certificate : newCertificates) {
            certificate.x509Certificate().checkValidity();
        }
    }

    private void validateSubjectDns(final List<Certificate> loadedCertificates, final List<Certificate> newCertificates)
        throws CertificateException {
        final List<String> currentSubjectDNs = loadedCertificates.stream().map(Certificate::subject).sorted().collect(Collectors.toList());
        final List<String> newSubjectDNs = newCertificates.stream().map(Certificate::subject).sorted().collect(Collectors.toList());
        if (!currentSubjectDNs.equals(newSubjectDNs)) {
            throw new CertificateException(
                "New certificates do not have valid Subject DNs. Current Subject DNs "
                    + currentSubjectDNs
                    + " new Subject DNs "
                    + newSubjectDNs
            );
        }
    }

    private void validateIssuerDns(final List<Certificate> loadedCertificates, final List<Certificate> newCertificates)
        throws CertificateException {
        final List<String> currentIssuerDNs = loadedCertificates.stream().map(Certificate::issuer).sorted().collect(Collectors.toList());
        final List<String> newIssuerDNs = newCertificates.stream().map(Certificate::issuer).sorted().collect(Collectors.toList());
        if (!currentIssuerDNs.equals(newIssuerDNs)) {
            throw new CertificateException(
                "New certificates do not have valid Issuer DNs. Current Issuer DNs: "
                    + currentIssuerDNs
                    + " new Issuer DNs: "
                    + newIssuerDNs
            );
        }
    }

    private void validateSans(final List<Certificate> loadedCertificates, final List<Certificate> newCertificates)
        throws CertificateException {
        final List<String> currentSans = loadedCertificates.stream()
            .map(Certificate::subjectAlternativeNames)
            .sorted()
            .collect(Collectors.toList());
        final List<String> newSans = newCertificates.stream()
            .map(Certificate::subjectAlternativeNames)
            .sorted()
            .collect(Collectors.toList());
        if (!currentSans.equals(newSans)) {
            throw new CertificateException(
                "New certificates do not have valid SANs. Current SANs: " + currentSans + " new SANs: " + newSans
            );
        }
    }

    private void validateNewKeyMaterialCertificates(
        final List<Certificate> loadedCertificates,
        final List<Certificate> newCertificates,
        boolean shouldValidateNewCertDNs
    ) throws CertificateException {
        validateDates(newCertificates);
        if (shouldValidateNewCertDNs) {
            validateSubjectDns(loadedCertificates, newCertificates);
            validateIssuerDns(loadedCertificates, newCertificates);
            validateSans(loadedCertificates, newCertificates);
        }
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
