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
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.ClientAuth;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.ssl.config.Certificate;

import static java.util.function.Predicate.not;

public class SslContextHandler {
    private final static Logger LOGGER = LogManager.getLogger(SslContextHandler.class);
    private final boolean isClient;
    private final SslConfiguration sslConfiguration;
    private final List<Certificate> loadedCertificates;

    private SSLContext sslContext;

    public SslContextHandler(final SslConfiguration sslConfiguration) {
        this(sslConfiguration, false);
    }

    public SslContextHandler(final SslConfiguration sslConfiguration, final boolean client) {
        this.isClient = client;
        this.sslConfiguration = sslConfiguration;
        this.loadedCertificates = sslConfiguration.certificates();
        this.sslContext = sslConfiguration.buildSSLContext(true, isClient);
    }

    public SslConfiguration sslConfiguration() {
        return sslConfiguration;
    }

    // public for tests
    SSLContext sslContext() {
        return sslContext;
    }

    public Stream<Certificate> certificates() {
        return Stream.concat(authorityCertificates(), keyMaterialCertificates())
            .sorted((c1, c2) -> Boolean.compare(c1.hasPrivateKey(), c2.hasPrivateKey()));
    }

    public Stream<Certificate> authorityCertificates() {
        return authorityCertificates(loadedCertificates);
    }

    public Stream<Certificate> keyMaterialCertificates() {
        return keyMaterialCertificates(loadedCertificates);
    }

    public SSLEngine createSSLEngine() {
        return configureSSLEngine(sslContext.createSSLEngine());
    }

    public SSLEngine createSSLEngine(final String hostname, final int port) {
        return configureSSLEngine(sslContext.createSSLEngine(hostname, port));
    }

    public boolean isClient(){ return isClient; }
    public boolean isServer(){ return !isClient; }

    SSLEngine configureSSLEngine(final SSLEngine engine) {
        engine.setEnabledCipherSuites(sslConfiguration.ciphers());
        engine.setEnabledProtocols(sslConfiguration.allowedProtocols());
        engine.setUseClientMode(isClient);
        if (!isClient) {
            switch (sslConfiguration.sslParameters().clientAuth()) {
                case ClientAuth.NONE:
                    engine.setWantClientAuth(false);
                    engine.setNeedClientAuth(false);
                    break;
                case ClientAuth.OPTIONAL:
                    engine.setWantClientAuth(true);
                    engine.setNeedClientAuth(false);
                    break;
                case ClientAuth.REQUIRE:
                    engine.setWantClientAuth(false);
                    engine.setNeedClientAuth(true);
                    break;
                default:
                    throw new IllegalStateException("Unexpected value: " + sslConfiguration.sslParameters().clientAuth());
            }
            SSLParameters sslParameters = sslContext.getDefaultSSLParameters();
            sslParameters.setApplicationProtocols(new String[]{
                    ApplicationProtocolNames.HTTP_2,
                    ApplicationProtocolNames.HTTP_1_1
            });
            engine.setSSLParameters(sslParameters);
        }
        return engine;
    }

    Stream<Certificate> authorityCertificates(final List<Certificate> certificates) {
        return certificates.stream().filter(not(Certificate::hasPrivateKey));
    }

    Stream<Certificate> keyMaterialCertificates(final List<Certificate> certificates) {
        return certificates.stream().filter(Certificate::hasPrivateKey);
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
            sslContext = sslConfiguration.buildSSLContext(false, isClient);
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
        final var sessionContext = this.isClient?
                sslContext.getClientSessionContext() :
                sslContext.getServerSessionContext();
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
