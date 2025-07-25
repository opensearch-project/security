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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator;

import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_HTTP_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_CLIENT_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_PREFIX;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SSL_TRANSPORT_SERVER_PREFIX;

/**
 * CertTypes identify the setting prefix under which configuration settings for a set of certificates
 * are located as well as the id which uniquely identifies a certificate type to the end user.
 * CertTypes have a 1-to-1 relationship with ssl contexts and are registered in the global
 * CERT_TYPE_REGISTRY but default for mandatory transports, or dynamically for pluggable auxiliary transports.
 */
public class CertType {
    private final String certSettingPrefix;
    private final String certID;

    /**
     * In most cases the certID is the last element of the setting prefix.
     * We expect this to be the case for all auxiliary transports.
     * Exceptions where this pattern does not hold include:
     * "plugins.security.ssl.transport.server."
     * "plugins.security.ssl.transport.client."
     * Where users identify these certificates respectively as:
     * "transport_server" & "transport_client"
     */
    public CertType(String certSettingPrefix) {
        this.certSettingPrefix = certSettingPrefix;
        String[] parts = certSettingPrefix.split("\\.");
        this.certID = parts[parts.length - 1].toLowerCase(Locale.ROOT);
    }

    public CertType(String certSettingPrefix, String certID) {
        this.certSettingPrefix = certSettingPrefix;
        this.certID = certID;
    }

    public String sslSettingPrefix() {
        return certSettingPrefix;
    }

    public String id() {
        return this.certID;
    }

    @Override
    public String toString() {
        return this.id();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CertType certType = (CertType) o;
        return this.id().equals(certType.id());
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.id());
    }

    /**
     * Write only set for tracking certificate types discovered and registered on a node.
     * Not all ssl context configurations are known at compile time, so we track newly discovered CertTypes here.
     */
    public static class NodeCertTypeRegistry implements Iterable<CertType> {
        private final Set<CertType> registeredCertType = new HashSet<>();

        public NodeCertTypeRegistry(CertType... initialCertTypes) {
            for (CertType certType : initialCertTypes) {
                register(certType);
            }
        }

        public void register(CertType certType) {
            registeredCertType.add(certType);
        }

        public boolean contains(CertType certType) {
            return registeredCertType.contains(certType);
        }

        public boolean contains(String certID) {
            for (CertType certType : registeredCertType) {
                if (Objects.equals(certType.id(), certID)) {
                    return true;
                }
            }
            return false;
        }

        @Nonnull
        @Override
        public Iterator<CertType> iterator() {
            return Collections.unmodifiableSet(registeredCertType).iterator();
        }
    }

    /*
    Mandatory transports.
    */
    public static CertType HTTP = new CertType(SSL_HTTP_PREFIX);
    public static CertType TRANSPORT = new CertType(SSL_TRANSPORT_PREFIX);
    public static CertType TRANSPORT_CLIENT = new CertType(SSL_TRANSPORT_CLIENT_PREFIX, "transport_client");
    public static final NodeCertTypeRegistry CERT_TYPE_REGISTRY = new NodeCertTypeRegistry(
        HTTP,
        TRANSPORT,
        TRANSPORT_CLIENT
    );

    /*
    Deprecated static certificate types.
    Only for backwards compatibility on node-to-node transport.
     */
    public enum LegacyCertType {
        HTTP,
        TRANSPORT,
        TRANSPORT_CLIENT;
    }
}
