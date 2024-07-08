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

package org.opensearch.security.dlic.rest.api.ssl;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Objects;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

public class CertificateInfo implements Writeable, ToXContent {

    private final String subject;

    private final String san;

    private final String issuer;

    private final String notAfter;

    private final String notBefore;

    public CertificateInfo(String subject, String san, String issuer, String notAfter, String notBefore) {
        this.subject = subject;
        this.san = san;
        this.issuer = issuer;
        this.notAfter = notAfter;
        this.notBefore = notBefore;
    }

    public CertificateInfo(final StreamInput in) throws IOException {
        this.subject = in.readOptionalString();
        this.san = in.readOptionalString();
        this.issuer = in.readOptionalString();
        this.notAfter = in.readOptionalString();
        this.notBefore = in.readOptionalString();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeOptionalString(subject);
        out.writeOptionalString(san);
        out.writeOptionalString(issuer);
        out.writeOptionalString(notAfter);
        out.writeOptionalString(notBefore);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        return builder.startObject()
            .field("subject_dn", subject)
            .field("san", san)
            .field("issuer_dn", issuer)
            .field("not_after", notAfter)
            .field("not_before", notAfter)
            .endObject();
    }

    public static CertificateInfo from(final X509Certificate x509Certificate, final String subjectAlternativeNames) {
        String subject = null;
        String issuer = null;
        String notAfter = null;
        String notBefore = null;
        if (x509Certificate != null) {
            if (x509Certificate.getSubjectX500Principal() != null) {
                subject = x509Certificate.getSubjectX500Principal().getName();
            }
            if (x509Certificate.getIssuerX500Principal() != null) {
                issuer = x509Certificate.getIssuerX500Principal().getName();
            }
            if (x509Certificate.getNotAfter() != null) {
                notAfter = x509Certificate.getNotAfter().toInstant().toString();
            }
            if (x509Certificate.getNotBefore() != null) {
                notBefore = x509Certificate.getNotBefore().toInstant().toString();
            }
        }
        return new CertificateInfo(subject, subjectAlternativeNames, issuer, notAfter, notBefore);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CertificateInfo that = (CertificateInfo) o;
        return Objects.equals(subject, that.subject)
            && Objects.equals(san, that.san)
            && Objects.equals(issuer, that.issuer)
            && Objects.equals(notAfter, that.notAfter)
            && Objects.equals(notBefore, that.notBefore);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subject, san, issuer, notAfter, notBefore);
    }
}
