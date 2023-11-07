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

import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;

public class SecurityX509CertificateBuilder extends X509CertificateBuilder {

    @Override
    public X509Certificate buildObject(final String namespaceURI, final String localName, final String namespacePrefix) {
        return new SecurityX509CertificateImpl(namespaceURI, localName, namespacePrefix);
    }

}
