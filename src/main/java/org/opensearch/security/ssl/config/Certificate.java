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

import java.security.cert.X509Certificate;
import java.util.Objects;

public class Certificate {

    private final X509Certificate certificate;

    private final String format;

    private final String alias;

    private final boolean hasKey;

    public Certificate(final X509Certificate certificate, final boolean hasKey) {
        this(certificate, "pem", null, hasKey);
    }

    public Certificate(final X509Certificate certificate, final String format, final String alias, final boolean hasKey) {
        this.certificate = certificate;
        this.format = format;
        this.alias = alias;
        this.hasKey = hasKey;
    }

    public X509Certificate x509Certificate() {
        return certificate;
    }

    public String format() {
        return format;
    }

    public String alias() {
        return alias;
    }

    public boolean hasPrivateKey() {
        return hasKey;
    }

    public String subjectAlternativeNames() {
        return SanParser.parse(certificate);
    }

    public byte[] signature() {
        return certificate.getSignature();
    }

    public String serialNumber() {
        return certificate.getSerialNumber().toString();
    }

    public String subject() {
        return certificate.getSubjectX500Principal() != null ? certificate.getSubjectX500Principal().getName() : null;
    }

    public String issuer() {
        return certificate.getIssuerX500Principal() != null ? certificate.getIssuerX500Principal().getName() : null;
    }

    public String notAfter() {
        return certificate.getNotAfter() != null ? certificate.getNotAfter().toInstant().toString() : null;
    }

    public String notBefore() {
        return certificate.getNotBefore() != null ? certificate.getNotBefore().toInstant().toString() : null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Certificate that = (Certificate) o;
        return hasKey == that.hasKey
            && Objects.equals(certificate, that.certificate)
            && Objects.equals(format, that.format)
            && Objects.equals(alias, that.alias);
    }

    @Override
    public int hashCode() {
        return Objects.hash(certificate, format, alias, hasKey);
    }

    @Override
    public String toString() {
        return "Certificate{" + "format='" + format + '\'' + ", alias='" + alias + '\'' + ", hasKey=" + hasKey + '}';
    }
}
