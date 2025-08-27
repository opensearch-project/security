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
import java.util.Objects;

import org.opensearch.Version;
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

    private final String format;

    private final String alias;

    private final boolean hasPrivateKey;

    private final String serialNumber;

    public CertificateInfo(
        String format,
        String alias,
        String serialNumber,
        boolean hasPrivateKey,
        String subject,
        String san,
        String issuer,
        String notAfter,
        String notBefore
    ) {
        this.format = format;
        this.alias = alias;
        this.serialNumber = serialNumber;
        this.hasPrivateKey = hasPrivateKey;
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
        if (in.getVersion().onOrAfter(Version.V_3_0_0)) {
            this.format = in.readOptionalString();
            this.alias = in.readOptionalString();
            this.serialNumber = in.readOptionalString();
            this.hasPrivateKey = in.readBoolean();
        }
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeOptionalString(subject);
        out.writeOptionalString(san);
        out.writeOptionalString(issuer);
        out.writeOptionalString(notAfter);
        out.writeOptionalString(notBefore);
        if (out.getVersion().onOrAfter(Version.V_3_0_0)) {
            out.writeOptionalString(format);
            out.writeOptionalString(alias);
            out.writeOptionalString(serialNumber);
            out.writeBoolean(hasPrivateKey);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        return builder.startObject()
            .field("format", format)
            .field("alias", alias)
            .field("subject_dn", subject)
            .field("san", san)
            .field("serial_number", serialNumber)
            .field("issuer_dn", issuer)
            .field("has_private_key", hasPrivateKey)
            .field("not_after", notAfter)
            .field("not_before", notAfter)
            .endObject();
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
