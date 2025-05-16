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

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.ssl.config.CertType;

public class CertificatesInfo implements Writeable, ToXContent {

    private final Map<CertType, List<CertificateInfo>> certificates;

    public CertificatesInfo(final Map<CertType, List<CertificateInfo>> certificates) {
        this.certificates = certificates;
    }

    public CertificatesInfo(final StreamInput in) throws IOException {
        certificates = in.readMap(CertType::new, listIn -> listIn.readList(CertificateInfo::new));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeMap(certificates, (streamOutput, certType) -> certType.writeTo(streamOutput), StreamOutput::writeList);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject("certificates");
        for (Map.Entry<CertType, List<CertificateInfo>> entry : certificates.entrySet()) {
            builder.field(entry.getKey().name(), certificates.get(entry.getKey()));
        }
        return builder.endObject();
    }
}
