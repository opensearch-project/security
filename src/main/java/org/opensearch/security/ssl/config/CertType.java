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

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;

import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_HTTP_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_CLIENT_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_PREFIX;

/**
 * CertTypes have a 1-to-1 relationship with ssl context configurations and identify
 * the setting prefix under which configuration settings are located.
 *
 * CertTypes are uniquely identified by their `certID` (the last element of their setting prefix)
 * as this is how users identify certs in the certificates info API.
 */
public class CertType implements Writeable {
    private final String sslConfigSettingPrefix;

    public static CertType HTTP = new CertType(SSL_HTTP_PREFIX);
    public static CertType TRANSPORT = new CertType(SSL_TRANSPORT_PREFIX);
    public static CertType TRANSPORT_CLIENT = new CertType(SSL_TRANSPORT_CLIENT_PREFIX);

    /*
     * REGISTERED_CERT_TYPES provides visibility of known configured certificates to certificates api.
     * {@link org.opensearch.security.dlic.rest.api.ssl.CertificatesInfoNodesRequest}.
     * Disabled or invalid cert configurations are still registered here.
     */
    public static final Set<CertType> REGISTERED_CERT_TYPES = new HashSet<>(Arrays.asList(HTTP, TRANSPORT, TRANSPORT_CLIENT));
    public static boolean certRegistered(String certID){
        for (CertType certType : REGISTERED_CERT_TYPES) {
            if (Objects.equals(certType.certID(), certID)) {
                return true;
            }
        }
        return false;
    }

    public CertType(String sslConfigSettingPrefix) {
        this.sslConfigSettingPrefix = sslConfigSettingPrefix;

    }

    public CertType(final StreamInput in) throws IOException {
        this.sslConfigSettingPrefix = in.readString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(sslConfigSettingPrefix);
    }

    public String sslSettingPrefix() {
        return sslConfigSettingPrefix;
    }

    public String certID() {
        String[] parts = sslConfigSettingPrefix.split("\\.");
        String id = parts[parts.length - 1];
        return id.toLowerCase(Locale.ROOT);
    }

    @Override
    public String toString() {
        return this.certID();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CertType certType = (CertType) o;
        return this.certID().equals(certType.certID());
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.certID());
    }
}
