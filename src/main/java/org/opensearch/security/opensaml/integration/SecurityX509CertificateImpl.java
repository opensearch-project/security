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

package org.opensearch.security.opensaml.integration;

import java.lang.ref.Cleaner;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.collection.IndexingObjectStore;
import org.opensaml.core.xml.AbstractXMLObject;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.xmlsec.signature.X509Certificate;

/**
 * The class was adapted from {@link org.opensaml.xmlsec.signature.impl.X509CertificateBuilder}.
 * The main reason is that it is only one way to set up {@link CleanerFactory}
 * together with cleaners daemon thread factory which is required for OpenSearch
 */
public class SecurityX509CertificateImpl extends AbstractXMLObject implements X509Certificate {

    private static final IndexingObjectStore<String> B64_CERT_STORE = new IndexingObjectStore<>();

    private static final Cleaner CLEANER = CleanerFactory.create(SecurityX509CertificateImpl.class);

    private Cleaner.Cleanable cleanable;

    private String b64CertIndex;

    protected SecurityX509CertificateImpl(final String namespaceURI, final String elementLocalName, final String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    @Override
    public String getValue() {
        return B64_CERT_STORE.get(b64CertIndex);
    }

    @Override
    public void setValue(final String newValue) {
        // Dump our cached DOM if the new value really is new
        final String currentCert = B64_CERT_STORE.get(b64CertIndex);
        final String newCert = prepareForAssignment(currentCert, newValue);

        // This is a new value, remove the old one, add the new one
        if (!Objects.equals(currentCert, newCert)) {
            if (cleanable != null) {
                cleanable.clean();
                cleanable = null;
            }
            b64CertIndex = B64_CERT_STORE.put(newCert);
            if (b64CertIndex != null) {
                cleanable = CLEANER.register(this, new SecurityX509CertificateImpl.CleanerState(b64CertIndex));
            }
        }
    }

    @Override
    public List<XMLObject> getOrderedChildren() {
        return Collections.emptyList();
    }

    static class CleanerState implements Runnable {

        private String index;

        public CleanerState(@Nonnull final String idx) {
            index = idx;
        }

        public void run() {
            SecurityX509CertificateImpl.B64_CERT_STORE.remove(index);
        }

    }
}
