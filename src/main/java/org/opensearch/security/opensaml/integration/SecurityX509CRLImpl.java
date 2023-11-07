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
import org.opensaml.xmlsec.signature.X509CRL;

/**
 * The class was adapted from {@link org.opensaml.xmlsec.signature.impl.X509CRLImpl}.
 * The main reason is that it is only one way to set up {@link CleanerFactory}
 * together with cleaners daemon thread factory which is required for OpenSearch
 */
public class SecurityX509CRLImpl extends AbstractXMLObject implements X509CRL {

    private static final IndexingObjectStore<String> B64_CRL_STORE = new IndexingObjectStore<>();

    private static final Cleaner CLEANER = CleanerFactory.create(SecurityX509CRLImpl.class);

    private Cleaner.Cleanable cleanable;

    private String b64CRLIndex;

    protected SecurityX509CRLImpl(final String namespaceURI, final String elementLocalName, final String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    public String getValue() {
        return B64_CRL_STORE.get(b64CRLIndex);
    }

    public void setValue(final String newValue) {
        // Dump our cached DOM if the new value really is new
        final String currentCRL = B64_CRL_STORE.get(b64CRLIndex);
        final String newCRL = prepareForAssignment(currentCRL, newValue);

        // This is a new value, remove the old one, add the new one
        if (!Objects.equals(currentCRL, newCRL)) {
            if (cleanable != null) {
                cleanable.clean();
                cleanable = null;
            }
            b64CRLIndex = B64_CRL_STORE.put(newCRL);
            if (b64CRLIndex != null) {
                cleanable = CLEANER.register(this, new SecurityX509CRLImpl.CleanerState(b64CRLIndex));
            }
        }
    }

    @Override
    public List<XMLObject> getOrderedChildren() {
        return Collections.emptyList();
    }

    static class CleanerState implements Runnable {

        /** The index to remove from the store. */
        private String index;

        public CleanerState(@Nonnull final String idx) {
            index = idx;
        }

        /** {@inheritDoc} */
        public void run() {
            SecurityX509CRLImpl.B64_CRL_STORE.remove(index);
        }

    }
}
