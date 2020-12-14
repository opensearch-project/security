/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.dlic.auth.http.saml;

import java.net.URL;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.metadata.resolver.MetadataResolver;

import com.amazon.dlic.auth.http.jwt.AbstractHTTPJwtAuthenticator;
import com.amazon.dlic.auth.http.jwt.keybyoidc.AuthenticatorUnavailableException;
import com.amazon.dlic.auth.http.jwt.keybyoidc.BadCredentialsException;
import com.amazon.dlic.auth.http.jwt.keybyoidc.KeyProvider;
import com.amazon.opendistroforelasticsearch.security.auth.Destroyable;
import com.amazon.opendistroforelasticsearch.security.auth.HTTPAuthenticator;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.PemKeyReader;
import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import com.google.common.base.Strings;
import com.onelogin.saml2.authn.AuthnRequest;
import com.onelogin.saml2.logout.LogoutRequest;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.DestructableComponent;
import org.opensaml.saml.metadata.resolver.impl.AbstractMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.DOMMetadataResolver;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;


public class HTTPSamlAuthenticator implements HTTPAuthenticator, Destroyable {
    protected final static Logger log = LogManager.getLogger(HTTPSamlAuthenticator.class);

    public static final String IDP_METADATA_URL = "idp.metadata_url";
    public static final String IDP_METADATA_FILE = "idp.metadata_file";
    public static final String IDP_METADATA_CONTENT = "idp.metadata_content";

    private static boolean openSamlInitialized = false;

    private String subjectKey;
    private String rolesKey;
    private String kibanaRootUrl;
    private String spSignatureAlgorithm;
    private Boolean useForceAuthn;
    private PrivateKey spSignaturePrivateKey;
    private Saml2SettingsProvider saml2SettingsProvider;
    private MetadataResolver metadataResolver;
    private AuthTokenProcessorHandler authTokenProcessorHandler;
    private HTTPJwtAuthenticator httpJwtAuthenticator;
    private Settings jwtSettings;

    private static int resolverIdCounter = 0;

    public HTTPSamlAuthenticator(final Settings settings, final Path configPath) {
        try {
            ensureOpenSamlInitialization();

            rolesKey = settings.get("roles_key");
            subjectKey = settings.get("subject_key");
            kibanaRootUrl = settings.get("kibana_url");
            spSignatureAlgorithm = settings.get("sp.signature_algorithm", Constants.RSA_SHA256);
            spSignaturePrivateKey = getSpSignaturePrivateKey(settings, configPath);
            useForceAuthn = settings.getAsBoolean("sp.forceAuthn", null);

            if (rolesKey == null || rolesKey.length() == 0) {
                log.warn("roles_key is not configured, will only extract subject from SAML");
                rolesKey = null;
            }

            if (subjectKey == null || subjectKey.length() == 0) {
                // If subjectKey == null, get subject from the NameID element.
                // Thus, this is a valid configuration.
                subjectKey = null;
            }

            if (kibanaRootUrl == null) {
                throw new Exception("kibana_url is unconfigured");
            }

            this.metadataResolver = createMetadataResolver(settings, configPath);

            this.saml2SettingsProvider = new Saml2SettingsProvider(settings, this.metadataResolver, spSignaturePrivateKey);

            try {
                this.saml2SettingsProvider.getCached();
            } catch (Exception e) {
                log.debug("Exception while initializing Saml2SettingsProvider. Possibly, the IdP is unreachable right now. This is recoverable by a meta data refresh.", e);
            }

            this.jwtSettings = this.createJwtAuthenticatorSettings(settings);

            this.authTokenProcessorHandler = new AuthTokenProcessorHandler(settings, jwtSettings,
                    this.saml2SettingsProvider);

            this.httpJwtAuthenticator = new HTTPJwtAuthenticator(this.jwtSettings, configPath);

        } catch (Exception e) {
            log.error("Error creating HTTPSamlAuthenticator: " + e + ". SAML authentication will not work", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public AuthCredentials extractCredentials(RestRequest restRequest, ThreadContext threadContext)
            throws ElasticsearchSecurityException {
        if ("/_opendistro/_security/api/authtoken".equals(restRequest.path())) {
            return null;
        }

        AuthCredentials authCredentials = this.httpJwtAuthenticator.extractCredentials(restRequest, threadContext);

        if ("/_opendistro/_security/authinfo".equals(restRequest.path())) {
            this.initLogoutUrl(restRequest, threadContext, authCredentials);
        }

        return authCredentials;
    }

    @Override
    public String getType() {
        return "saml";
    }

    @Override
    public boolean reRequestAuthentication(RestChannel restChannel, AuthCredentials authCredentials) {
        try {
            RestRequest restRequest = restChannel.request();

            if ("/_opendistro/_security/api/authtoken".equals(restRequest.path())
                    && this.authTokenProcessorHandler.handle(restRequest, restChannel)) {
                return true;
            }

            Saml2Settings saml2Settings = this.saml2SettingsProvider.getCached();
            BytesRestResponse authenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED, "");

            authenticateResponse.addHeader("WWW-Authenticate", getWwwAuthenticateHeader(saml2Settings));

            restChannel.sendResponse(authenticateResponse);

            return true;
        } catch (Exception e) {
            log.error("Error in reRequestAuthentication()", e);
            return false;
        }
    }

    private String getWwwAuthenticateHeader(Saml2Settings saml2Settings) throws Exception {
        AuthnRequest authnRequest = this.buildAuthnRequest(saml2Settings);

        return "X-Security-IdP realm=\"Open Distro Security\" location=\""
                + StringEscapeUtils.escapeJava(getSamlRequestRedirectBindingLocation(IdpEndpointType.SSO, saml2Settings,
                        authnRequest.getEncodedAuthnRequest(true)))
                + "\" requestId=\"" + StringEscapeUtils.escapeJava(authnRequest.getId()) + "\"";
    }

    private AuthnRequest buildAuthnRequest(Saml2Settings saml2Settings) {
        boolean forceAuthn = false;

        if (this.useForceAuthn != null) {
            forceAuthn = this.useForceAuthn.booleanValue();
        } else {
            if (!this.isSingleLogoutAvailable(saml2Settings)) {
                forceAuthn = true;
            }
        }

        return new AuthnRequest(saml2Settings, forceAuthn, false, true);
    }

    private PrivateKey getSpSignaturePrivateKey(Settings settings, Path configPath) throws Exception {
        try {
            PrivateKey result = PemKeyReader.loadKeyFromStream(settings.get("sp.signature_private_key_password"),
                    PemKeyReader.resolveStream("sp.signature_private_key", settings));

            if (result == null) {
                result = PemKeyReader.loadKeyFromFile(settings.get("sp.signature_private_key_password"),
                        PemKeyReader.resolve("sp.signature_private_key_filepath", settings, configPath, false));
            }

            return result;
        } catch (Exception e) {
            throw new Exception("Invalid value for sp.signature_private_key", e);
        }
    }

    private URL getIdpUrl(IdpEndpointType endpointType, Saml2Settings saml2Settings) {
        if (endpointType == IdpEndpointType.SSO) {
            return saml2Settings.getIdpSingleSignOnServiceUrl();
        } else {
            return saml2Settings.getIdpSingleLogoutServiceUrl();
        }
    }

    private boolean isSingleLogoutAvailable(Saml2Settings saml2Settings) {
        return saml2Settings.getIdpSingleLogoutServiceUrl() != null;
    }

    @Override
    public void destroy() {
        if (this.metadataResolver instanceof DestructableComponent) {
            ((DestructableComponent) this.metadataResolver).destroy();
        }
    }

    static void ensureOpenSamlInitialization() {
        if (openSamlInitialized) {
            return;
        }

        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
                @Override
                public Void run() throws InitializationException {

                    Thread thread = Thread.currentThread();
                    ClassLoader originalClassLoader = thread.getContextClassLoader();

                    try {

                        thread.setContextClassLoader(InitializationService.class.getClassLoader());

                        InitializationService.initialize();

                        new org.opensaml.saml.config.impl.XMLObjectProviderInitializer().init();
                        new org.opensaml.saml.config.impl.SAMLConfigurationInitializer().init();
                        new org.opensaml.xmlsec.config.impl.XMLObjectProviderInitializer().init();
                    } finally {
                        thread.setContextClassLoader(originalClassLoader);
                    }

                    openSamlInitialized = true;
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            throw new RuntimeException(e.getCause());
        }
    }

    private MetadataResolver createMetadataResolver(final Settings settings, final Path configPath)
            throws Exception {
        final AbstractMetadataResolver metadataResolver;

        final String idpMetadataUrl = settings.get(IDP_METADATA_URL);
        final String idpMetadataFile = settings.get(IDP_METADATA_FILE);
        final String idpMetadataBody = settings.get(IDP_METADATA_CONTENT);
        if (idpMetadataUrl != null) {
            metadataResolver = new SamlHTTPMetadataResolver(idpMetadataUrl, settings, configPath);
        } else if (idpMetadataFile != null) {
            metadataResolver = new SamlFilesystemMetadataResolver(idpMetadataFile, settings, configPath);
        } else if (idpMetadataBody != null) {
            metadataResolver = new DOMMetadataResolver(getMetadataDOM(idpMetadataBody));
        } else {
            throw new Exception(String.format("One of %s, %s or %s must be configured", IDP_METADATA_URL, IDP_METADATA_FILE, IDP_METADATA_CONTENT));
        }

        metadataResolver.setId(HTTPSamlAuthenticator.class.getName() + "_" + (++resolverIdCounter));
        metadataResolver.setRequireValidMetadata(true);
        metadataResolver.setFailFastInitialization(false);
        final BasicParserPool basicParserPool = new BasicParserPool();
        basicParserPool.initialize();
        metadataResolver.setParserPool(basicParserPool);

        SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
                @Override
                public Void run() throws ComponentInitializationException {
                    metadataResolver.initialize();
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof ComponentInitializationException) {
                throw (ComponentInitializationException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }

        return metadataResolver;

    }

    private Settings createJwtAuthenticatorSettings(Settings settings) {
        Settings.Builder settingsBuilder = Settings.builder();
        Settings jwtSettings = settings.getAsSettings("jwt");

        settingsBuilder.put(jwtSettings);

        if (jwtSettings.get("roles_key") == null) {
            settingsBuilder.put("roles_key", settings.get("roles_key", "roles"));
        }

        if (jwtSettings.get("subject_key") == null) {
            settingsBuilder.put("subject_key", settings.get("subject_key", "sub"));
        }

        return settingsBuilder.build();
    }

    String buildLogoutUrl(AuthCredentials authCredentials) {
        try {
            if (authCredentials == null) {
                return null;
            }

            Saml2Settings saml2Settings = this.saml2SettingsProvider.getCached();

            if (!isSingleLogoutAvailable(saml2Settings)) {
                return null;
            }

            String nameIdClaim = this.subjectKey == null ? "sub" : "saml_ni";
            String nameId = authCredentials.getAttributes().get("attr.jwt." + nameIdClaim);
            String nameIdFormat = SamlNameIdFormat
                    .getByShortName(authCredentials.getAttributes().get("attr.jwt.saml_nif")).getUri();
            String sessionIndex = authCredentials.getAttributes().get("attr.jwt.saml_si");

            LogoutRequest logoutRequest = new LogoutRequest(saml2Settings, null, nameId, sessionIndex, nameIdFormat);

            return getSamlRequestRedirectBindingLocation(IdpEndpointType.SLO, saml2Settings,
                    logoutRequest.getEncodedLogoutRequest(true));

        } catch (Exception e) {
            log.error("Error while creating logout URL. Logout will be not available", e);
            return null;
        }

    }

    private void initLogoutUrl(RestRequest restRequest, ThreadContext threadContext, AuthCredentials authCredentials) {
        threadContext.putTransient(ConfigConstants.SSO_LOGOUT_URL, buildLogoutUrl(authCredentials));
    }

    private String getSamlRequestRedirectBindingLocation(IdpEndpointType idpEndpointType, Saml2Settings saml2Settings,
            String samlRequest) throws Exception {

        URL idpUrl = getIdpUrl(idpEndpointType, saml2Settings);

        if (Strings.isNullOrEmpty(idpUrl.getQuery())) {
            return getIdpUrl(idpEndpointType, saml2Settings) + "?" + this.getSamlRequestQueryString(samlRequest);
        } else {
            return getIdpUrl(idpEndpointType, saml2Settings) + "&" + this.getSamlRequestQueryString(samlRequest);
        }

    }

    private String getSamlRequestQueryString(String samlRequest) throws Exception {

        if (this.spSignaturePrivateKey == null) {
            return "SAMLRequest=" + Util.urlEncoder(samlRequest);
        }

        String queryString = "SAMLRequest=" + Util.urlEncoder(samlRequest) + "&SigAlg="
                + Util.urlEncoder(this.spSignatureAlgorithm);

        String signature = getSamlRequestQueryStringSignature(queryString);

        queryString += "&Signature=" + Util.urlEncoder(signature);

        return queryString;
    }

    private String getSamlRequestQueryStringSignature(String samlRequestQueryString) throws Exception {
        try {
            return Util.base64encoder(
                    Util.sign(samlRequestQueryString, this.spSignaturePrivateKey, this.spSignatureAlgorithm));
        } catch (Exception e) {
            throw new Exception("Error while signing SAML request", e);
        }
    }

    private static Element getMetadataDOM(final String xmlString) throws IOException, SAXException, ParserConfigurationException {
        try {
            Document doc = Util.loadXML(xmlString.trim());
            return doc.getDocumentElement();
        } catch (Exception e) {
            log.error("Error while parsing SAML Metadata Body {}", xmlString, e);
            throw e;
        }
    }

    class HTTPJwtAuthenticator extends AbstractHTTPJwtAuthenticator {

        public HTTPJwtAuthenticator(Settings settings, Path configPath) {
            super(settings, configPath);
        }

        @Override
        public String getType() {
            return null;
        }

        @Override
        protected KeyProvider initKeyProvider(Settings settings, Path configPath) throws Exception {
            return new KeyProvider() {

                @Override
                public JsonWebKey getKeyAfterRefresh(String kid)
                        throws AuthenticatorUnavailableException, BadCredentialsException {
                    return authTokenProcessorHandler.getSigningKey();
                }

                @Override
                public JsonWebKey getKey(String kid) throws AuthenticatorUnavailableException, BadCredentialsException {
                    return authTokenProcessorHandler.getSigningKey();
                }
            };
        }

    }

    private enum IdpEndpointType {
        SSO, SLO
    }
}
