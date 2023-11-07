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

import org.opensaml.xmlsec.signature.X509CRL;
import org.opensaml.xmlsec.signature.impl.X509CRLBuilder;

public class SecurityX509CRLBuilder extends X509CRLBuilder {

    public X509CRL buildObject(final String namespaceURI, final String localName, final String namespacePrefix) {
        return new SecurityX509CRLImpl(namespaceURI, localName, namespacePrefix);
    }

}
