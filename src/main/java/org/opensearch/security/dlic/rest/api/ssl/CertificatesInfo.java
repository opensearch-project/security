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
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.opensearch.Version;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.ssl.config.CertType;

public class CertificatesInfo implements Writeable, ToXContent {
    private final Map<String, List<CertificateInfo>> certificates;

    public CertificatesInfo(final Map<String, List<CertificateInfo>> certificates) {
        this.certificates = certificates;
    }

    public CertificatesInfo(final StreamInput in) throws IOException {
        if (in.getVersion().onOrAfter(Version.V_3_2_0)) {
            certificates = in.readMap(
                StreamInput::readString,
                listIn -> listIn.readList(CertificateInfo::new)
            );
        } else {
            /*
            Previous versions represent cert types with an enum and serialize based on
            enum ordinal. To maintain backwards compatibility we fall back to mapping these
            enum ordinals to the appropriate native certificate type.
             */
            certificates = in.readMap(
                (StreamInput streamIn) -> switch (streamIn.readEnum(CertType.LegacyCertType.class)) {
                    case CertType.LegacyCertType.HTTP -> CertType.HTTP.id();
                    case CertType.LegacyCertType.TRANSPORT -> CertType.TRANSPORT.id();
                    case CertType.LegacyCertType.TRANSPORT_CLIENT -> CertType.TRANSPORT_CLIENT.id();
                },
                listIn -> listIn.readList(CertificateInfo::new)
            );
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        if (out.getVersion().onOrAfter(Version.V_3_2_0)) {
            out.writeMap(certificates, StreamOutput::writeString, StreamOutput::writeList);
        } else {
            /*
            We need to write only map elements which previous versions will understand.
            CertTypes are strictly bound to LegacyCertType enum in these versions and only has knowledge of
            HTTP, TRANSPORT, TRANSPORT_CLIENT.
             */
            Set<String> legacyCerts = certificates.keySet();
            legacyCerts.retainAll(List.of(
                    CertType.HTTP.id(),
                    CertType.TRANSPORT.id(),
                    CertType.TRANSPORT_CLIENT.id()
            ));
            out.writeVInt(legacyCerts.size());
            for (String certId : legacyCerts) {
                if (CertType.HTTP.id().equals(certId)) {
                    out.writeEnum(CertType.LegacyCertType.HTTP);
                } else if (CertType.TRANSPORT.id().equals(certId)) {
                    out.writeEnum(CertType.LegacyCertType.TRANSPORT);
                } else if (CertType.TRANSPORT_CLIENT.id().equals(certId)) {
                    out.writeEnum(CertType.LegacyCertType.TRANSPORT_CLIENT);
                }
                out.writeList(certificates.get(certId));
            }
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject("certificates");
        for (Map.Entry<String, List<CertificateInfo>> entry : certificates.entrySet()) {
            builder.field(entry.getKey(), certificates.get(entry.getKey()));
        }
        return builder.endObject();
    }
}
