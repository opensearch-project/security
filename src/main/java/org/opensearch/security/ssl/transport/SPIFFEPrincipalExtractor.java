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

package org.opensearch.security.ssl.transport;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.secure_sm.AccessController;

public class SPIFFEPrincipalExtractor implements PrincipalExtractor {
    /**
     * PrincipalExtractor implementation that extracts a SPIFFE URI from an X.509 certificate's SAN.
     * Returns "CN=spiffe://..." if found, otherwise null.
     * Used for SPIFFE X.509 SVID-based authentication in OpenSearch clusters.
     */

    protected final Logger log = LogManager.getLogger(this.getClass());

    @Override
    public String extractPrincipal(final X509Certificate x509Certificate, final Type type) {
        if (x509Certificate == null) {
            return null;
        }

        final Collection<List<?>> altNames = AccessController.doPrivileged(() -> {
            try {
                return x509Certificate.getSubjectAlternativeNames();
            } catch (CertificateParsingException e) {
                log.error("Unable to parse X509 altNames", e);
                return null;
            }
        });

        if (altNames == null) {
            return null;
        }

        for (List<?> sanItem : altNames) {
            if (sanItem == null || sanItem.size() < 2) {
                continue;
            }
            Integer altNameType = (Integer) sanItem.get(0);
            Object altNameValue = sanItem.get(1);
            if (altNameType != null && altNameType == 6 && altNameValue instanceof String) {
                String uriValue = (String) altNameValue;
                if (uriValue.startsWith("spiffe://")) {
                    if (log.isTraceEnabled()) {
                        log.trace("principal: CN={}", uriValue);
                    }
                    return String.format("CN=%s", uriValue);
                }
            }
        }
        return null;
    }
}
