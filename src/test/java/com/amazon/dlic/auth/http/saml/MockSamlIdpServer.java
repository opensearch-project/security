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

package com.amazon.dlic.auth.http.saml;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.URISyntaxException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.apache.hc.core5.function.Callback;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentLengthStrategy;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.config.Http1Config;
import org.apache.hc.core5.http.impl.bootstrap.HttpServer;
import org.apache.hc.core5.http.impl.bootstrap.ServerBootstrap;
import org.apache.hc.core5.http.impl.io.DefaultBHttpServerConnection;
import org.apache.hc.core5.http.io.HttpConnectionFactory;
import org.apache.hc.core5.http.io.HttpMessageParserFactory;
import org.apache.hc.core5.http.io.HttpMessageWriterFactory;
import org.apache.hc.core5.http.io.HttpRequestHandler;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHttpRequest;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.net.URIBuilder;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLProtocolContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.binding.security.impl.SAML2HTTPRedirectDeflateSignatureSecurityHandler;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.w3c.dom.Document;

import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.network.SocketUtils;

class MockSamlIdpServer implements Closeable {

    final static String ENTITY_ID = "http://test.entity";

    final static String CTX_METADATA = "/metadata";
    final static String CTX_SAML_SSO = "/saml/sso";
    final static String CTX_SAML_SLO = "/saml/slo";

    private HttpServer httpServer;
    private final int port;
    private final String uri;
    private final boolean ssl;
    private boolean encryptAssertion = false;
    private boolean wantAuthnRequestsSigned;
    private String idpEntityId;
    private X509Certificate signingCertificate;
    private Credential signingCredential;
    private String authenticateUser;
    private List<String> authenticateUserRoles;
    private int baseId = 1;
    private boolean signResponses = true;
    private X509Certificate spSignatureCertificate;
    private String endpointQueryString;
    private String defaultAssertionConsumerService;

    MockSamlIdpServer() throws IOException {
        this(SocketUtils.findAvailableTcpPort());
    }

    MockSamlIdpServer(int port) throws IOException {
        this(port, false, ENTITY_ID, null);
    }

    MockSamlIdpServer(int port, boolean ssl, String idpEntityId, String endpointQueryString) throws IOException {
        this.port = port;
        this.uri = (ssl ? "https" : "http") + "://localhost:" + port;
        this.ssl = ssl;
        this.idpEntityId = idpEntityId;
        this.endpointQueryString = endpointQueryString;

        this.loadSigningKeys("saml/kirk-keystore.jks", "kirk");

        ServerBootstrap serverBootstrap = ServerBootstrap.bootstrap().setListenerPort(port)
                .register(CTX_METADATA, new HttpRequestHandler() {

                    @Override
                    public void handle(ClassicHttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException, IOException {

                        handleMetadataRequest(request, response, context);

                    }
                }).register(CTX_SAML_SSO, new HttpRequestHandler() {

                    @Override
                    public void handle(ClassicHttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException, IOException {
                        handleSsoRequest(request, response, context);
                    }
                }).register(CTX_SAML_SLO, new HttpRequestHandler() {

                    @Override
                    public void handle(ClassicHttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException, IOException {
                        handleSloRequest(request, response, context);
                    }
                });

        if (ssl) {

            serverBootstrap = serverBootstrap.setSslContext(createSSLContext())
                    .setSslSetupHandler(new Callback<SSLParameters>() {
                        @Override
                        public void execute(SSLParameters object) {
                            object.setNeedClientAuth(true);
                        }
                    })
                    .setConnectionFactory(new HttpConnectionFactory<DefaultBHttpServerConnection>() {
                        @Override
                        public DefaultBHttpServerConnection createConnection(final Socket socket) throws IOException {
                            final DefaultBHttpServerConnection conn = new DefaultBHttpServerConnection(ssl ? "https" : "http", Http1Config.DEFAULT);
                            conn.bind(socket);
                            return conn;
                        }
                    });
        }

        this.httpServer = serverBootstrap.create();
    }

    public void start() throws IOException {

        httpServer.start();

    }

    @Override
    public void close() throws IOException {
        httpServer.stop();
    }

    public HttpServer getHttpServer() {
        return httpServer;
    }

    public String getUri() {
        if (endpointQueryString != null) {
            return uri + "?" + endpointQueryString;
        } else {
            return uri;
        }
    }

    public String getMetadataUri() {
        if (endpointQueryString != null) {
            return uri + CTX_METADATA + "?" + endpointQueryString;
        } else {
            return uri + CTX_METADATA;
        }
    }

    public String getSamlSsoUri() {
        if (endpointQueryString != null) {
            return uri + CTX_SAML_SSO + "?" + endpointQueryString;
        } else {
            return uri + CTX_SAML_SSO;
        }
    }

    public String getSamlSloUri() {
        if (endpointQueryString != null) {
            return uri + CTX_SAML_SLO + "?" + endpointQueryString;
        } else {
            return uri + CTX_SAML_SLO;
        }
    }

    public int getPort() {
        return port;
    }

    protected void handleMetadataRequest(HttpRequest request, ClassicHttpResponse response, HttpContext context)
            throws HttpException, IOException {
        response.setCode(200);
        response.setHeader("Cache-Control", "public, max-age=31536000");
        response.setHeader("Content-Type", "application/xml");
        response.setEntity(new StringEntity(createMetadata()));
    }

    protected void handleSsoRequest(HttpRequest request, HttpResponse response, HttpContext context)
            throws HttpException, IOException {

        if ("GET".equalsIgnoreCase(request.getMethod())) {
            handleSsoGetRequestBase(request);
        } else {
            response.setCode(405);
        }

    }

    protected void handleSloRequest(HttpRequest request, HttpResponse response, HttpContext context)
            throws HttpException, IOException {

        if ("GET".equalsIgnoreCase(request.getMethod())) {
            handleSloGetRequestBase(request);
        } else {
            response.setCode(405);
        }
    }

    public String handleSsoGetRequestURI(String samlRequestURI) {
        return handleSsoGetRequestBase(new BasicHttpRequest("GET", samlRequestURI));
    }

    public String handleSsoGetRequestBase(HttpRequest request) {
        try {

            HttpServletRequest httpServletRequest = new FakeHttpServletRequest(request);

            HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
            decoder.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
            decoder.setHttpServletRequest(httpServletRequest);
            decoder.initialize();
            decoder.decode();

            MessageContext<SAMLObject> messageContext = decoder.getMessageContext();

            if (!(messageContext.getMessage() instanceof AuthnRequest)) {
                throw new RuntimeException("Expected AuthnRequest; received: " + messageContext.getMessage());
            }

            AuthnRequest authnRequest = (AuthnRequest) messageContext.getMessage();

            return createSamlAuthResponse(authnRequest);
        } catch (URISyntaxException | ComponentInitializationException | MessageDecodingException e) {
            throw new RuntimeException(e);
        }
    }

    public String createUnsolicitedSamlResponse() {
        return createSamlAuthResponse(null);
    }

    public void handleSloGetRequestURI(String samlRequestURI) {
        handleSloGetRequestBase(new BasicHttpRequest("GET", samlRequestURI));
    }

    @SuppressWarnings("unchecked")
    public void handleSloGetRequestBase(HttpRequest request) {
        try {

            HttpServletRequest httpServletRequest = new FakeHttpServletRequest(request);

            HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
            decoder.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
            decoder.setHttpServletRequest(httpServletRequest);
            decoder.initialize();
            decoder.decode();

            MessageContext<SAMLObject> messageContext = decoder.getMessageContext();

            if (!(messageContext.getMessage() instanceof LogoutRequest)) {
                throw new RuntimeException("Expected LogoutRequest; received: " + messageContext.getMessage());
            }

            LogoutRequest logoutRequest = (LogoutRequest) messageContext.getMessage();

            SAML2HTTPRedirectDeflateSignatureSecurityHandler signatureSecurityHandler = new SAML2HTTPRedirectDeflateSignatureSecurityHandler();
            SignatureValidationParameters validationParams = new SignatureValidationParameters();
            SecurityParametersContext securityParametersContext = messageContext
                    .getSubcontext(SecurityParametersContext.class, true);

            SAMLPeerEntityContext peerEntityContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
            peerEntityContext.setEntityId(idpEntityId);
            peerEntityContext.setRole(org.opensaml.saml.saml2.metadata.SPSSODescriptor.DEFAULT_ELEMENT_NAME);

            SAMLProtocolContext protocolContext = messageContext.getSubcontext(SAMLProtocolContext.class, true);
            protocolContext.setProtocol(SAMLConstants.SAML20P_NS);

            validationParams.setSignatureTrustEngine(buildSignatureTrustEngine(this.spSignatureCertificate));
            securityParametersContext.setSignatureValidationParameters(validationParams);
            signatureSecurityHandler.setHttpServletRequest(httpServletRequest);
            signatureSecurityHandler.initialize();
            signatureSecurityHandler.invoke(messageContext);

            if (!this.authenticateUser.equals(logoutRequest.getNameID().getValue())) {
                throw new RuntimeException("Unexpected NameID in LogoutRequest: " + logoutRequest);
            }

        } catch (URISyntaxException | ComponentInitializationException | MessageDecodingException
                | MessageHandlerException e) {
            throw new RuntimeException(e);
        }
    }

    private String createSamlAuthResponse(AuthnRequest authnRequest) {
        try {
            Response response = createSamlElement(Response.class);
            response.setID(nextId());

            if (authnRequest != null) {
                response.setInResponseTo(authnRequest.getID());
            }

            response.setVersion(SAMLVersion.VERSION_20);
            response.setStatus(createStatus(StatusCode.SUCCESS));
            response.setIssueInstant(new DateTime());

            Assertion assertion = createSamlElement(Assertion.class);

            assertion.setID(nextId());
            assertion.setIssueInstant(new DateTime());
            assertion.setIssuer(createIssuer());

            AuthnStatement authnStatement = createSamlElement(AuthnStatement.class);
            assertion.getAuthnStatements().add(authnStatement);

            authnStatement.setAuthnInstant(new DateTime());
            authnStatement.setSessionIndex(nextId());
            authnStatement.setAuthnContext(createAuthnCotext());

            Subject subject = createSamlElement(Subject.class);
            assertion.setSubject(subject);

            subject.setNameID(createNameID(NameIDType.UNSPECIFIED, authenticateUser));

            if (authnRequest != null) {
                subject.getSubjectConfirmations()
                        .add(createSubjectConfirmation("urn:oasis:names:tc:SAML:2.0:cm:bearer",
                                new DateTime().plusMinutes(1), authnRequest.getID(),
                                authnRequest.getAssertionConsumerServiceURL()));
            } else {
                subject.getSubjectConfirmations().add(createSubjectConfirmation("urn:oasis:names:tc:SAML:2.0:cm:bearer",
                        new DateTime().plusMinutes(1), null, defaultAssertionConsumerService));
            }

            Conditions conditions = createSamlElement(Conditions.class);
            assertion.setConditions(conditions);

            conditions.setNotBefore(new DateTime());
            conditions.setNotOnOrAfter(new DateTime().plusMinutes(1));

            if (authenticateUserRoles != null) {
                AttributeStatement attributeStatement = createSamlElement(AttributeStatement.class);
                assertion.getAttributeStatements().add(attributeStatement);

                Attribute attribute = createSamlElement(Attribute.class);
                attributeStatement.getAttributes().add(attribute);

                attribute.setName("roles");
                attribute.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:basic");

                for (String role : authenticateUserRoles) {
                    attribute.getAttributeValues().add(createXSAny(AttributeValue.DEFAULT_ELEMENT_NAME, role));
                }
            }
            
            if (signResponses) {
                Signature signature = createSamlElement(Signature.class);
                assertion.setSignature(signature);

                signature.setSigningCredential(this.signingCredential);
                signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
                signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

                XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);

                Signer.signObject(signature);
            }

            if (this.encryptAssertion){
                Encrypter encrypter = getEncrypter();
                EncryptedAssertion encryptedAssertion = encrypter.encrypt(assertion);
                response.getEncryptedAssertions().add(encryptedAssertion);
            } else {
                response.getAssertions().add(assertion);
            }


            String marshalledXml = marshallSamlXml(response);

            return Base64Support.encode(marshalledXml.getBytes("UTF-8"), Base64Support.UNCHUNKED);

        } catch (MarshallingException | SignatureException | UnsupportedEncodingException | EncryptionException e) {
            throw new RuntimeException(e);
        }
    }

    private Encrypter getEncrypter() {
        KeyEncryptionParameters kek = new KeyEncryptionParameters();
        // Algorithm from https://santuario.apache.org/Java/api/constant-values.html#org.apache.xml.security.utils.EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15
        kek.setAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-1_5");
        kek.setEncryptionCredential(new BasicX509Credential(spSignatureCertificate));
        Encrypter encrypter = new Encrypter( new DataEncryptionParameters(),kek);
        encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);
        return encrypter;
    }

    @SuppressWarnings("unchecked")
    public static <T> T createSamlElement(final Class<T> clazz) {
        try {
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

            QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);

            return (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
        } catch (NoSuchFieldException | IllegalArgumentException | IllegalAccessException | SecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public XSAny createXSAny(QName elementName, String textContent) {

        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        XSAny result = (XSAny) builderFactory.getBuilder(XSAny.TYPE_NAME).buildObject(elementName);

        result.setTextContent(textContent);

        return result;
    }

    private NameIDFormat createNameIDFormat(String format) {

        NameIDFormat nameIdFormat = createSamlElement(NameIDFormat.class);

        nameIdFormat.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

        return nameIdFormat;
    }

    private Status createStatus(String statusCodeValue) {
        Status status = createSamlElement(Status.class);
        StatusCode statusCode = createSamlElement(StatusCode.class);
        statusCode.setValue(statusCodeValue);
        status.setStatusCode(statusCode);
        return status;
    }

    private NameID createNameID(String format, String value) {
        NameID nameID = createSamlElement(NameID.class);
        nameID.setFormat(format);
        nameID.setValue(value);
        return nameID;
    }

    private SubjectConfirmation createSubjectConfirmation(String method, DateTime notOnOrAfter, String inResponseTo,
            String recipient) {
        SubjectConfirmation result = createSamlElement(SubjectConfirmation.class);
        result.setMethod(method);

        SubjectConfirmationData subjectConfirmationData = createSamlElement(SubjectConfirmationData.class);
        result.setSubjectConfirmationData(subjectConfirmationData);

        subjectConfirmationData.setInResponseTo(inResponseTo);
        subjectConfirmationData.setNotOnOrAfter(notOnOrAfter);
        subjectConfirmationData.setRecipient(recipient);

        return result;

    }

    private Issuer createIssuer() {
        Issuer issuer = createSamlElement(Issuer.class);
        issuer.setValue(this.idpEntityId);
        return issuer;
    }

    private AuthnContext createAuthnCotext() {
        AuthnContext authnContext = createSamlElement(AuthnContext.class);
        AuthnContextClassRef authnContextClassRef = createSamlElement(AuthnContextClassRef.class);
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.UNSPECIFIED_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        return authnContext;
    }

    private String createMetadata() {
        try {
            EntityDescriptor idpEntityDescriptor = createSamlElement(EntityDescriptor.class);
            idpEntityDescriptor.setEntityID(idpEntityId);

            IDPSSODescriptor idpSsoDescriptor = createSamlElement(IDPSSODescriptor.class);
            idpEntityDescriptor.getRoleDescriptors().add(idpSsoDescriptor);

            idpSsoDescriptor.setWantAuthnRequestsSigned(wantAuthnRequestsSigned);
            idpSsoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

            SingleLogoutService redirectSingleLogoutService = createSamlElement(SingleLogoutService.class);
            idpSsoDescriptor.getSingleLogoutServices().add(redirectSingleLogoutService);

            redirectSingleLogoutService.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
            redirectSingleLogoutService.setLocation(getSamlSloUri());

            idpSsoDescriptor.getNameIDFormats()
                    .add(createNameIDFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"));

            SingleSignOnService redirectSingleSignOnService = createSamlElement(SingleSignOnService.class);
            idpSsoDescriptor.getSingleSignOnServices().add(redirectSingleSignOnService);

            redirectSingleSignOnService.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
            redirectSingleSignOnService.setLocation(getSamlSsoUri());

            X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
            keyInfoGeneratorFactory.setEmitEntityCertificate(true);
            KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

            KeyDescriptor signingKeyDescriptor = createSamlElement(KeyDescriptor.class);
            idpSsoDescriptor.getKeyDescriptors().add(signingKeyDescriptor);

            signingKeyDescriptor.setUse(UsageType.SIGNING);

            signingKeyDescriptor
                    .setKeyInfo(keyInfoGenerator.generate(new BasicX509Credential(this.signingCertificate)));

            return marshallSamlXml(idpEntityDescriptor);
        } catch (org.opensaml.security.SecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private String marshallSamlXml(XMLObject xmlObject) {
        try {
            Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(xmlObject);
            out.marshall(xmlObject, document);

            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            DOMSource source = new DOMSource(document);
            StringWriter stringWriter = new StringWriter();

            transformer.transform(source, new StreamResult(stringWriter));
            return stringWriter.toString();
        } catch (ParserConfigurationException | MarshallingException | TransformerFactoryConfigurationError
                | TransformerException e) {
            throw new RuntimeException(e);
        }
    }

    private SignatureTrustEngine buildSignatureTrustEngine(X509Certificate certificate) {
        CredentialResolver credentialResolver = new StaticCredentialResolver(new BasicX509Credential(certificate));
        KeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(
                new BasicX509Credential(certificate));

        return new ExplicitKeySignatureTrustEngine(credentialResolver, keyInfoCredentialResolver);
    }

    void loadSigningKeys(String path, String alias) {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

            KeyStore keyStore = KeyStore.getInstance("JKS");
            InputStream keyStream = new FileInputStream(FileHelper.getAbsoluteFilePathFromClassPath(path).toFile());

            keyStore.load(keyStream, "changeit".toCharArray());
            kmf.init(keyStore, "changeit".toCharArray());

            this.signingCertificate = (X509Certificate) keyStore.getCertificate(alias);

            this.signingCredential = new BasicX509Credential(this.signingCertificate,
                    (PrivateKey) keyStore.getKey(alias, "changeit".toCharArray()));

        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException
                | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private SSLContext createSSLContext() {
        if (!this.ssl) {
            return null;
        }

        try {
            final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            final KeyStore trustStore = KeyStore.getInstance("JKS");
            InputStream trustStream = new FileInputStream(
                    FileHelper.getAbsoluteFilePathFromClassPath("jwt/truststore.jks").toFile());
            trustStore.load(trustStream, "changeit".toCharArray());
            tmf.init(trustStore);

            final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            final KeyStore keyStore = KeyStore.getInstance("JKS");
            InputStream keyStream = new FileInputStream(
                    FileHelper.getAbsoluteFilePathFromClassPath("jwt/node-0-keystore.jks").toFile());

            keyStore.load(keyStream, "changeit".toCharArray());
            kmf.init(keyStore, "changeit".toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return sslContext;
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String nextId() {
        return "MOCKSAML_" + (this.baseId++);
    }

    static class SSLTestHttpServerConnection extends DefaultBHttpServerConnection {
        public SSLTestHttpServerConnection(final String scheme, Http1Config http1Config,
                                           final CharsetDecoder charDecoder, final CharsetEncoder charEncoder,
                                           final ContentLengthStrategy incomingContentStrategy,
                                           final ContentLengthStrategy outgoingContentStrategy,
                                           final HttpMessageParserFactory<ClassicHttpRequest> requestParserFactory,
                                           final HttpMessageWriterFactory<ClassicHttpResponse> responseWriterFactory) {
            super(scheme, http1Config, charDecoder, charEncoder, incomingContentStrategy,
                    outgoingContentStrategy, requestParserFactory, responseWriterFactory);
        }
    }

    static class FakeHttpServletRequest implements HttpServletRequest {
        private final HttpRequest delegate;
        private final Map<String, String> queryParams;
        private final URIBuilder uriBuilder;

        FakeHttpServletRequest(HttpRequest delegate) throws URISyntaxException {
            this.delegate = delegate;
            String uri = delegate.getRequestUri();
            this.uriBuilder = new URIBuilder(uri);
            this.queryParams = uriBuilder.getQueryParams().stream()
                    .collect(Collectors.toMap(NameValuePair::getName, NameValuePair::getValue));
        }

        @Override
        public Object getAttribute(String arg0) {
            return null;
        }

        @SuppressWarnings("rawtypes")
        @Override
        public Enumeration getAttributeNames() {
            return Collections.emptyEnumeration();
        }

        @Override
        public String getCharacterEncoding() {
            if (delegate instanceof ClassicHttpRequest) {
                return ((ClassicHttpRequest) delegate).getEntity().getContentEncoding();
            } else {
                return null;
            }
        }

        @Override
        public int getContentLength() {
            if (delegate instanceof ClassicHttpRequest) {
                return (int) ((ClassicHttpRequest) delegate).getEntity().getContentLength();
            } else {
                return 0;
            }
        }

        @Override
        public String getContentType() {
            if (delegate instanceof ClassicHttpRequest) {
                return ((ClassicHttpRequest) delegate).getEntity().getContentType();
            } else {
                return null;
            }
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (delegate instanceof ClassicHttpRequest) {
                final InputStream in = ((ClassicHttpRequest) delegate).getEntity().getContent();

                return new ServletInputStream() {

                    public int read() throws IOException {
                        return in.read();
                    }

                    public int available() throws IOException {
                        return in.available();
                    }

                    public void close() throws IOException {
                        in.close();
                    }
                };
            } else {
                return null;
            }
        }

        @Override
        public String getLocalAddr() {
            return null;
        }

        @Override
        public String getLocalName() {
            return null;
        }

        @Override
        public int getLocalPort() {
            return 0;
        }

        @Override
        public Locale getLocale() {
            return null;
        }

        @SuppressWarnings("rawtypes")
        @Override
        public Enumeration getLocales() {
            return null;
        }

        @Override
        public String getParameter(String name) {
            return this.queryParams.get(name);
        }

        @SuppressWarnings("rawtypes")
        @Override
        public Map getParameterMap() {
            return Collections.unmodifiableMap(this.queryParams);
        }

        @SuppressWarnings("rawtypes")
        @Override
        public Enumeration getParameterNames() {
            return Collections.enumeration(this.queryParams.keySet());
        }

        @Override
        public String[] getParameterValues(String name) {
            String value = this.queryParams.get(name);

            if (value != null) {
                return new String[] { value };
            } else {
                return null;
            }
        }

        @Override
        public String getProtocol() {
            return null;
        }

        @Override
        public BufferedReader getReader() throws IOException {
            if (delegate instanceof ClassicHttpRequest) {
                final InputStream in = ((ClassicHttpRequest) delegate).getEntity().getContent();

                return new BufferedReader(new InputStreamReader(in));
            } else {
                return null;
            }
        }

        @Override
        public String getRealPath(String arg0) {
            return null;
        }

        @Override
        public String getRemoteAddr() {
            return null;
        }

        @Override
        public String getRemoteHost() {
            return null;
        }

        @Override
        public int getRemotePort() {
            return 0;
        }

        @Override
        public RequestDispatcher getRequestDispatcher(String arg0) {
            return null;
        }

        @Override
        public String getScheme() {
            return null;
        }

        @Override
        public String getServerName() {
            return null;
        }

        @Override
        public int getServerPort() {
            return 0;
        }

        @Override
        public boolean isSecure() {
            return false;
        }

        @Override
        public void removeAttribute(String arg0) {

        }

        @Override
        public void setAttribute(String arg0, Object arg1) {

        }

        @Override
        public void setCharacterEncoding(String arg0) throws UnsupportedEncodingException {

        }

        @Override
        public String getAuthType() {
            return null;
        }

        @Override
        public String getContextPath() {
            return null;
        }

        @Override
        public Cookie[] getCookies() {
            return null;
        }

        @Override
        public long getDateHeader(String arg0) {
            return 0;
        }

        @Override
        public String getHeader(String name) {
            Header header = delegate.getFirstHeader(name);

            if (header != null) {
                return header.getValue();
            } else {
                return null;
            }
        }

        @SuppressWarnings("rawtypes")
        @Override
        public Enumeration getHeaderNames() {
            return Collections.enumeration(
                    Arrays.asList(delegate.getHeaders()).stream().map(Header::getName).collect(Collectors.toSet()));
        }

        @SuppressWarnings("rawtypes")
        @Override
        public Enumeration getHeaders(String name) {
            Header[] headers = delegate.getHeaders(name);

            if (headers != null) {
                return Collections
                        .enumeration(Arrays.asList(headers).stream().map(Header::getName).collect(Collectors.toSet()));
            } else {
                return null;
            }
        }

        @Override
        public int getIntHeader(String name) {
            Header header = delegate.getFirstHeader(name);

            if (header != null) {
                return Integer.parseInt(header.getValue());
            } else {
                return 0;
            }
        }

        @Override
        public String getMethod() {
            return delegate.getMethod();
        }

        @Override
        public String getPathInfo() {
            return null;
        }

        @Override
        public String getPathTranslated() {
            return uriBuilder.getPath();
        }

        @Override
        public String getQueryString() {
            return this.delegate.getRequestUri().replaceAll("^.*\\?", "");
        }

        @Override
        public String getRemoteUser() {
            return null;
        }

        @Override
        public String getRequestURI() {
            return delegate.getRequestUri();
        }

        @Override
        public StringBuffer getRequestURL() {
            return new StringBuffer(delegate.getRequestUri());
        }

        @Override
        public String getRequestedSessionId() {
            return null;
        }

        @Override
        public String getServletPath() {
            return null;
        }

        @Override
        public HttpSession getSession() {
            return null;
        }

        @Override
        public HttpSession getSession(boolean arg0) {
            return null;
        }

        @Override
        public Principal getUserPrincipal() {
            return null;
        }

        @Override
        public boolean isRequestedSessionIdFromCookie() {
            return false;
        }

        @Override
        public boolean isRequestedSessionIdFromURL() {
            return false;
        }

        @Override
        public boolean isRequestedSessionIdFromUrl() {
            return false;
        }

        @Override
        public boolean isRequestedSessionIdValid() {
            return false;
        }

        @Override
        public boolean isUserInRole(String arg0) {
            return false;
        }
    }

    public String getIdpEntityId() {
        return idpEntityId;
    }

    public String getAuthenticateUser() {
        return authenticateUser;
    }

    public void setAuthenticateUser(String authenticateUser) {
        this.authenticateUser = authenticateUser;
    }

    public List<String> getAuthenticateUserRoles() {
        return authenticateUserRoles;
    }

    public void setAuthenticateUserRoles(List<String> authenticateUserRoles) {
        this.authenticateUserRoles = authenticateUserRoles;
    }

    public boolean isSignResponses() {
        return signResponses;
    }

    public void setSignResponses(boolean signResponses) {
        this.signResponses = signResponses;
    }

    public void setEncryptAssertion(boolean encryptAssertion) {
        this.encryptAssertion = encryptAssertion;
    }

    public X509Certificate getSpSignatureCertificate() {
        return spSignatureCertificate;
    }

    public void setSpSignatureCertificate(X509Certificate spSignatureCertificate) {
        this.spSignatureCertificate = spSignatureCertificate;
    }

    public String getEndpointQueryString() {
        return endpointQueryString;
    }

    public void setEndpointQueryString(String endpointQueryString) {
        this.endpointQueryString = endpointQueryString;
    }

    public String getDefaultAssertionConsumerService() {
        return defaultAssertionConsumerService;
    }

    public void setDefaultAssertionConsumerService(String defaultAssertionConsumerService) {
        this.defaultAssertionConsumerService = defaultAssertionConsumerService;
    }
}
