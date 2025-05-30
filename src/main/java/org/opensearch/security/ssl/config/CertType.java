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
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import javax.annotation.Nonnull;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;

import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_HTTP_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_CLIENT_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_SERVER_PREFIX;

/**
 * CertTypes have a 1-to-1 relationship with ssl contexts and identify
 * the setting prefix under which configuration settings are located.
 * CertTypes are uniquely identified by a `certID` which is used as the key for registering CertTypes on a node
 * and fetching certificate info through a CertificatesInfoNodesRequest.
 */
public class CertType implements Writeable {
    private final String sslConfigSettingPrefix;

    public static CertType HTTP = new CertType(SSL_HTTP_PREFIX);
    public static CertType TRANSPORT = new CertType(SSL_TRANSPORT_PREFIX);
    public static CertType TRANSPORT_CLIENT = new CertType(SSL_TRANSPORT_CLIENT_PREFIX) {
        @Override
        public String certID() {
            return "transport_client";
        }
    };
    public static CertType TRANSPORT_SERVER = new CertType(SSL_TRANSPORT_SERVER_PREFIX) {
        @Override
        public String certID() {
            return "transport_server";
        }
    };

    public static class NodeCertTypeRegistry implements Iterable<CertType> {
        private final Set<CertType> RegisteredCertType = new HashSet<>();

        public NodeCertTypeRegistry(CertType... initialCertTypes) {
            for (CertType certType : initialCertTypes) {
                register(certType);
            }
        }

        public void register(CertType certType) {
            if (RegisteredCertType.contains(certType)) {
                throw new IllegalArgumentException("Cert type " + certType + " is already registered in CertType registry");
            }
            RegisteredCertType.add(certType);
        }

        public boolean contains(CertType certType) {
            return RegisteredCertType.contains(certType);
        }

        public boolean contains(String certID) {
            for (CertType certType : RegisteredCertType) {
                if (Objects.equals(certType.certID(), certID)) {
                    return true;
                }
            }
            return false;
        }

        @Nonnull
        @Override
        public Iterator<CertType> iterator() {
            return Collections.unmodifiableSet(RegisteredCertType).iterator();
        }
    }

    /*
    Write only map for tracking certificates type discovered and registered on a node.
    Not all ssl context configurations are known at compile time, so we track newly discovered CertTypes here.
    */
    public static final NodeCertTypeRegistry CERT_TYPE_REGISTRY = new NodeCertTypeRegistry(
        HTTP,
        TRANSPORT,
        TRANSPORT_CLIENT,
        TRANSPORT_SERVER
    );

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
