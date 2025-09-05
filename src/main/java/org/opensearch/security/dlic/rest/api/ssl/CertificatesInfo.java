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
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.opensearch.Version;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

public class CertificatesInfo implements Writeable, ToXContent {
    private final Map<String, List<CertificateInfo>> certificates;

    public CertificatesInfo(final Map<String, List<CertificateInfo>> certificates) {
        this.certificates = certificates;
    }

    public CertificatesInfo(final StreamInput in) throws IOException {
        if (in.getVersion().before(Version.V_3_0_0)) {
            Map<CertificateType_2_19, List<CertificateInfo>> compatMap = in.readMap(
                keyIn -> keyIn.readEnum(CertificateType_2_19.class),
                listIn -> listIn.readList(CertificateInfo::new)
            );
            certificates = new HashMap<>();
            for (Map.Entry<CertificateType_2_19, List<CertificateInfo>> entry : compatMap.entrySet()) {
                certificates.put(entry.getKey().value(), entry.getValue());
            }
        } else {
            certificates = in.readMap(StreamInput::readString, listIn -> listIn.readList(CertificateInfo::new));
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        if (out.getVersion().before(Version.V_3_0_0)) {
            Map<CertificateType_2_19, List<CertificateInfo>> compatMap = new HashMap<>();
            for (Map.Entry<String, List<CertificateInfo>> entry : certificates.entrySet()) {
                if (Set.of("http", "transport").contains(entry.getKey().toLowerCase(Locale.ROOT))) {
                    compatMap.put(CertificateType_2_19.from(entry.getKey()), entry.getValue());
                }
            }
            out.writeMap(compatMap, StreamOutput::writeEnum, StreamOutput::writeList);
        } else {
            out.writeMap(certificates, StreamOutput::writeString, StreamOutput::writeList);
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

    public enum CertificateType_2_19 {
        HTTP("http"),
        TRANSPORT("transport"),
        ALL("all");

        private final String value;

        private CertificateType_2_19(String value) {
            this.value = value;
        }

        public static boolean isHttp(final CertificateType_2_19 certificateType) {
            return certificateType == HTTP || certificateType == ALL;
        }

        public static boolean isTransport(final CertificateType_2_19 certificateType) {
            return certificateType == TRANSPORT || certificateType == ALL;
        }

        public String value() {
            return value.toLowerCase(Locale.ROOT);
        }

        public static CertificateType_2_19 from(final String certType) {
            if (certType == null) {
                return ALL;
            }
            for (final var t : values())
                if (t.value.equalsIgnoreCase(certType)) return t;
            throw new IllegalArgumentException("Invalid certificate type: " + certType);
        }

    }
}
