package com.amazon.dlic.auth.http.saml;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.opensaml.saml.metadata.resolver.impl.DOMMetadataResolver;

import java.io.IOException;
import java.io.StringReader;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class SamlDOMMetadataResolver extends DOMMetadataResolver {
    protected final static Logger log = LogManager.getLogger(SamlDOMMetadataResolver.class);

    private static int componentIdCounter = 0;

    public SamlDOMMetadataResolver(Settings settings) throws Exception {
        super(getMetadataDOM(settings));
        setId(HTTPSamlAuthenticator.class.getName() + "_" + (++componentIdCounter));
        setRequireValidMetadata(true);
        setFailFastInitialization(false);
        BasicParserPool basicParserPool = new BasicParserPool();
        basicParserPool.initialize();
        setParserPool(basicParserPool);
    }

    private static Element getMetadataDOM(Settings settings) throws Exception {
        String xmlString = settings.get("idp.metadata_body", null);

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);

        //API to obtain DOM Document instance
        DocumentBuilder builder = null;
        try
        {
            builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlString)));
            return doc.getDocumentElement();
        } catch (Exception e)
        {
            log.error("Error while parsing SAML Metadata Body "+ e, e);
            throw e;
        }
    }
}
