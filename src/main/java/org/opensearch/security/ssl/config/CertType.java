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
 */
public class CertType implements Writeable {
    private final String sslConfigPrefix;
    private final String certTypeKey;

    public static CertType HTTP = new CertType(SSL_HTTP_PREFIX, "http");
    public static CertType TRANSPORT = new CertType(SSL_TRANSPORT_PREFIX, "transport");
    public static CertType TRANSPORT_CLIENT = new CertType(SSL_TRANSPORT_CLIENT_PREFIX, "transport_client");

    /*
     * REGISTERED_CERT_TYPES provides visibility of known configured certificates to certificates api.
     * {@link org.opensearch.security.dlic.rest.api.ssl.CertificatesInfoNodesRequest}.
     * Disabled or invalid cert configurations are still registered here.
     */
    public static final Set<CertType> REGISTERED_CERT_TYPES = new HashSet<>(Arrays.asList(HTTP, TRANSPORT, TRANSPORT_CLIENT));

    public CertType(String sslConfigPrefix, String certTypeKey) {
        this.sslConfigPrefix = sslConfigPrefix;
        this.certTypeKey = certTypeKey;
    }

    public CertType(final StreamInput in) throws IOException {
        this.sslConfigPrefix = in.readString();
        this.certTypeKey = in.readString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(sslConfigPrefix);
        out.writeString(certTypeKey);
    }

    public String sslConfigPrefix() {
        return sslConfigPrefix;
    }

    public String name() {
        return certTypeKey;
    }
}
