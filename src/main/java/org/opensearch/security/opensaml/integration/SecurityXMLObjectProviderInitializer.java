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

import java.io.IOException;
import java.io.InputStream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import net.shibboleth.utilities.java.support.primitive.StringSupport;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.config.XMLConfigurationException;
import org.opensaml.core.xml.config.XMLConfigurator;
import org.opensaml.xmlsec.config.impl.XMLObjectProviderInitializer;
import org.opensaml.xmlsec.signature.impl.X509CRLBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.w3c.dom.Element;

/**
 * The class extends {@link org.opensaml.xmlsec.config.impl.XMLObjectProviderInitializer}
 * which is responsible to map signature configuration from SAML
 * .well-known XML to the OpenSAML object model
 */
public class SecurityXMLObjectProviderInitializer extends XMLObjectProviderInitializer {

    protected final static Logger log = LogManager.getLogger(SecurityXMLObjectProviderInitializer.class);

    static final class SecurityObjectProviderXMLConfigurator extends XMLConfigurator {

        public static final String X509_CERTIFICATE_BUILDER_CLASS_NAME = X509CertificateBuilder.class.getCanonicalName();

        public static final String X509_CRL_BUILDER_CLASS_NAME = X509CRLBuilder.class.getCanonicalName();

        public SecurityObjectProviderXMLConfigurator() throws XMLConfigurationException {
            super();
        }

        @Override
        protected Object createClassInstance(Element configuration) throws XMLConfigurationException {
            final String className = StringSupport.trimOrNull(configuration.getAttributeNS(null, "className"));
            if (X509_CERTIFICATE_BUILDER_CLASS_NAME.equals(className)) {
                log.trace("Replace instance of {} with {}", className, SecurityX509CertificateBuilder.class.getCanonicalName());
                return new SecurityX509CertificateBuilder();
            } else if (X509_CRL_BUILDER_CLASS_NAME.equals(className)) {
                log.trace("Replace instance of {} with {}", className, SecurityX509CRLBuilder.class.getCanonicalName());
                return new SecurityX509CRLBuilder();
            } else {
                return super.createClassInstance(configuration);
            }
        }

    }

    @Override
    public void init() throws InitializationException {
        try {
            final XMLConfigurator configurator = new SecurityObjectProviderXMLConfigurator();
            for (String resource : getConfigResources()) {
                if (resource.startsWith("/")) {
                    resource = resource.substring(1);
                }
                log.debug("Loading XMLObject provider configuration from resource '{}'", resource);
                try (final InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(resource)) {
                    if (is != null) {
                        configurator.load(is);
                    } else {
                        throw new XMLConfigurationException("Resource not found: " + resource);
                    }
                } catch (final IOException e) {
                    throw new XMLConfigurationException("Error loading resource: " + resource, e);
                }
            }
        } catch (final XMLConfigurationException e) {
            log.error("Problem loading configuration resource: {}", e.getMessage());
            throw new InitializationException("Problem loading configuration resource", e);
        }
    }
}
