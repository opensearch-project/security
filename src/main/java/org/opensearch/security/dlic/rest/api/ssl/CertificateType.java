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

import java.util.Locale;

public enum CertificateType {
    HTTP("http"),
    TRANSPORT("transport"),
    ALL("all");

    private final String value;

    private CertificateType(String value) {
        this.value = value;
    }

    public static boolean isHttp(final CertificateType certificateType) {
        return certificateType == HTTP || certificateType == ALL;
    }

    public static boolean isTransport(final CertificateType certificateType) {
        return certificateType == TRANSPORT || certificateType == ALL;
    }

    public String value() {
        return value.toLowerCase(Locale.ROOT);
    }

    public static CertificateType from(final String certType) {
        if (certType == null) {
            return ALL;
        }
        for (final var t : values())
            if (t.value.equalsIgnoreCase(certType)) return t;
        throw new IllegalArgumentException("Invalid certificate type: " + certType);
    }

}
