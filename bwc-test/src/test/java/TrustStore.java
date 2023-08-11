/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.commons.rest;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * Helper class to read raw pem files to keystore.
 */
public class TrustStore {

    private final String effectiveKeyAlias = "al";
    private final String storeType = "JKS";
    private final String certType = "X.509";
    private final String cert;

    public TrustStore(final String file) {
        cert = file;
    }

    public KeyStore create() throws IOException, GeneralSecurityException {
        X509Certificate[] trustCerts = loadCertificatesFromFile(cert);
        return toTrustStore(effectiveKeyAlias, trustCerts);
    }

    private X509Certificate[] loadCertificatesFromFile(String file) throws IOException, GeneralSecurityException {
        if (file == null) {
            return null;
        }
        CertificateFactory fact = CertificateFactory.getInstance(certType);
        try (FileInputStream is = new FileInputStream(file)) {
            Collection<? extends Certificate> certs = fact.generateCertificates(is);
            X509Certificate[] x509Certs = new X509Certificate[certs.size()];
            int i = 0;
            for (Certificate cert : certs) {
                x509Certs[i++] = (X509Certificate) cert;
            }
            return x509Certs;
        }
    }

    private KeyStore toTrustStore(final String trustCertificatesAliasPrefix, final X509Certificate[] trustCertificates) throws IOException,
        GeneralSecurityException {
        if (trustCertificates == null) {
            return null;
        }
        KeyStore ks = KeyStore.getInstance(storeType);
        ks.load(null);

        if (trustCertificates != null) {
            for (int i = 0; i < trustCertificates.length; i++) {
                X509Certificate x509Certificate = trustCertificates[i];
                ks.setCertificateEntry(trustCertificatesAliasPrefix + "_" + i, x509Certificate);
            }
        }
        return ks;
    }
}
