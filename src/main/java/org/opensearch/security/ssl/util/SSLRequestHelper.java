/*
 * Copyright 2015-2017 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.opensearch.security.ssl.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.security.cert.TrustAnchor;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.env.Environment;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.transport.PrincipalExtractor.Type;

import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD;

public class SSLRequestHelper {

    private static final Logger log = LogManager.getLogger(SSLRequestHelper.class);

    public static class SSLInfo {
        private final X509Certificate[] x509Certs;
        private final X509Certificate[] localCertificates;
        private final String principal;
        private final String protocol;
        private final String cipher;

        public SSLInfo(
            final X509Certificate[] x509Certs,
            final String principal,
            final String protocol,
            final String cipher,
            X509Certificate[] localCertificates
        ) {
            super();
            this.x509Certs = x509Certs;
            this.principal = principal;
            this.protocol = protocol;
            this.cipher = cipher;
            this.localCertificates = localCertificates;
        }

        public X509Certificate[] getX509Certs() {
            return x509Certs == null ? null : x509Certs.clone();
        }

        public X509Certificate[] getLocalCertificates() {
            return localCertificates == null ? null : localCertificates.clone();
        }

        public String getPrincipal() {
            return principal;
        }

        public String getProtocol() {
            return protocol;
        }

        public String getCipher() {
            return cipher;
        }

        @Override
        public String toString() {
            return "SSLInfo [x509Certs="
                + Arrays.toString(x509Certs)
                + ", principal="
                + principal
                + ", protocol="
                + protocol
                + ", cipher="
                + cipher
                + "]";
        }

    }

    public static SSLInfo getSSLInfo(
        final Settings settings,
        final Path configPath,
        final SecurityRequest request,
        PrincipalExtractor principalExtractor
    ) throws SSLPeerUnverifiedException {
        final SSLEngine engine = request.getSSLEngine();
        if (engine == null) {
            return null;
        }

        final SSLSession session = engine.getSession();

        X509Certificate[] x509Certs = null;
        final String protocol = session.getProtocol();
        final String cipher = session.getCipherSuite();
        String principal = null;

        if (engine.getNeedClientAuth() || engine.getWantClientAuth()) {
            Certificate[] certs = null;
            try {
                certs = session.getPeerCertificates();
            } catch (SSLPeerUnverifiedException e) {
                // deal with 'null' certs down below
            }

            if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                x509Certs = Arrays.copyOf(certs, certs.length, X509Certificate[].class);

                try {
                    validate(x509Certs, settings, configPath);
                } catch (CertPathValidatorException e) {
                    log.error(
                        "Certificate is revoked or path invalid for '{}' (reason: {})",
                        x509Certs[0].getSubjectX500Principal(),
                        e.getReason()
                    );
                    throw new SSLPeerUnverifiedException(e.getMessage(), e);
                } catch (CertificateException e) {
                    // Log the full cause chain so the root reason from BC FIPS is visible
                    log.error(
                        "Certificate revocation check failed for '{}'",
                        x509Certs[0].getSubjectX500Principal(),
                        e
                    );
                    throw new SSLPeerUnverifiedException(e.getMessage(), e);
                } catch (IOException e) {
                    log.warn(
                        "CRL/OCSP infrastructure unreachable (check CRL file path or OCSP/CRLDP network access): {}",
                        e.getMessage()
                    );
                    throw new SSLPeerUnverifiedException(e.getMessage(), e);
                } catch (GeneralSecurityException e) {
                    log.error(
                        "Certificate revocation check configuration error",
                        e
                    );
                    throw new SSLPeerUnverifiedException(e.getMessage(), e);
                }

                principal = principalExtractor == null ? null : principalExtractor.extractPrincipal(x509Certs[0], Type.HTTP);
            } else if (engine.getNeedClientAuth()) {
                throw new OpenSearchException("No client certificates found but such are needed (SG 9).");
            }
        }

        X509Certificate[] localCerts = null;
        if (session.getLocalCertificates() != null) {
            localCerts = Arrays.stream(session.getLocalCertificates()).map(X509Certificate.class::cast).toArray(X509Certificate[]::new);
        }

        return new SSLInfo(
            x509Certs,
            principal,
            protocol,
            cipher,
            localCerts
        );
    }

    public static boolean containsBadHeader(final ThreadContext context, String prefix) {
        if (context != null) {
            for (final String key : context.getHeaders().keySet()) {
                if (key.trim().toLowerCase().startsWith(prefix)) {
                    return true;
                }
            }
        }

        return false;
    }

    static void validate(X509Certificate[] x509Certs, final Settings settings, final Path configPath)
        throws IOException, GeneralSecurityException {

        final boolean validateCrl = settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, false);
        log.trace("validateCrl: {}", validateCrl);

        if (!validateCrl) {
            return;
        }

        final Environment env = new Environment(settings, configPath);
        final Collection<? extends CRL> crls = loadCrls(settings, env);
        final CertificateValidator validator = buildValidator(settings, env, crls);
        configureValidator(validator, settings);
        validator.validate(x509Certs);
    }

    static Collection<? extends CRL> loadCrls(final Settings settings, final Environment env) throws IOException,
        GeneralSecurityException {
        final String crlFile = settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_FILE);
        if (crlFile == null) {
            log.trace("no crl file configured");
            return null;
        }

        final File crl = env.configDir().resolve(crlFile).toAbsolutePath().toFile();
        try (FileInputStream crlin = new FileInputStream(crl)) {
            final Collection<? extends CRL> crls = CertificateFactory.getInstance("X.509").generateCRLs(crlin);
            log.trace("crls from file: {}", crls.size());
            return crls;
        }
    }

    static CertificateValidator buildValidator(
        final Settings settings,
        final Environment env,
        final Collection<? extends CRL> crls
    ) throws IOException, GeneralSecurityException {
        final String truststore = settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH);
        if (truststore != null) {
            return buildValidatorFromTruststore(settings, env, crls, truststore);
        } else {
            return buildValidatorFromPem(settings, env, crls);
        }
    }

    static CertificateValidator buildValidatorFromTruststore(
        final Settings settings,
        final Environment env,
        final Collection<? extends CRL> crls,
        final String truststore
    ) throws IOException, GeneralSecurityException {
        final String defaultStoreType = CryptoServicesRegistrar.isInApprovedOnlyMode() ? "BCFKS" : "JKS";
        final String truststoreType = settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, defaultStoreType);
        final String truststorePassword = SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD.getSetting(settings);
        final KeyStore ts = KeyStore.getInstance(truststoreType);
        try (FileInputStream fin = new FileInputStream(env.configDir().resolve(truststore).toAbsolutePath().toString())) {
            ts.load(fin, (truststorePassword == null || truststorePassword.isEmpty()) ? null : truststorePassword.toCharArray());
        }
        return new CertificateValidator(trustAnchorsFrom(ts), crls);
    }

    static CertificateValidator buildValidatorFromPem(
        final Settings settings,
        final Environment env,
        final Collection<? extends CRL> crls
    ) throws IOException, GeneralSecurityException {
        final File trustedCas = env.configDir()
            .resolve(settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, ""))
            .toAbsolutePath()
            .toFile();
        try (FileInputStream trin = new FileInputStream(trustedCas)) {
            final Collection<? extends Certificate> certs = CertificateFactory.getInstance("X.509").generateCertificates(trin);
            final X509Certificate[] trustedCerts = certs.stream().map(X509Certificate.class::cast).toArray(X509Certificate[]::new);
            return new CertificateValidator(trustAnchorsFrom(trustedCerts), crls);
        }
    }

    static Set<TrustAnchor> trustAnchorsFrom(final KeyStore trustStore) throws GeneralSecurityException {
        final Set<TrustAnchor> anchors = new HashSet<>();
        for (Enumeration<String> aliases = trustStore.aliases(); aliases.hasMoreElements();) {
            final String alias = aliases.nextElement();
            if (trustStore.isCertificateEntry(alias)) {
                anchors.add(new TrustAnchor((X509Certificate) trustStore.getCertificate(alias), null));
            }
        }
        return anchors;
    }

    public static Set<TrustAnchor> trustAnchorsFrom(final X509Certificate... certs) {
        return Arrays.stream(certs)
            .map(cert -> new TrustAnchor(cert, null))
            .collect(Collectors.toSet());
    }

    static void configureValidator(final CertificateValidator validator, final Settings settings) {
        validator.setEnableCRLDP(!settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP, false));
        validator.setEnableOCSP(!settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_OCSP, false));
        validator.setCheckOnlyEndEntities(settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_CHECK_ONLY_END_ENTITIES, true));
        validator.setPreferCrl(settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP, false));

        Long dateTimestamp = settings.getAsLong(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATION_DATE, null);
        if (dateTimestamp != null && dateTimestamp < 0) {
            dateTimestamp = null;
        }
        validator.setDate(dateTimestamp == null ? null : new Date(dateTimestamp));
    }
}
