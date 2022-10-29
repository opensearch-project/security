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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.base.Strings;
import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.exception.ValidationError;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.util.Util;
import org.apache.commons.lang3.StringUtils;
import org.apache.cxf.jaxrs.json.basic.JsonMapObjectReaderWriter;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.KeyType;
import org.apache.cxf.rs.security.jose.jwk.PublicKeyUse;
import org.apache.cxf.rs.security.jose.jws.JwsUtils;
import org.apache.cxf.rs.security.jose.jwt.JoseJwtProducer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.cxf.rs.security.jose.jwt.JwtUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.xml.sax.SAXException;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.rest.RestStatus;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.api.AuthTokenProcessorAction;

class AuthTokenProcessorHandler {
    private static final Logger log = LogManager.getLogger(AuthTokenProcessorHandler.class);
    private static final Logger token_log = LogManager.getLogger("com.amazon.dlic.auth.http.saml.Token");
    private static final Pattern EXPIRY_SETTINGS_PATTERN = Pattern.compile("\\s*(\\w+)\\s*(?:\\+\\s*(\\w+))?\\s*");

    private Saml2SettingsProvider saml2SettingsProvider;
    private JoseJwtProducer jwtProducer;
    private String jwtSubjectKey;
    private String jwtRolesKey;
    private String samlSubjectKey;
    private String samlRolesKey;
    private String kibanaRootUrl;

    private long expiryOffset = 0;
    private ExpiryBaseValue expiryBaseValue = ExpiryBaseValue.AUTO;
    private JsonWebKey signingKey;
    private JsonMapObjectReaderWriter jsonMapReaderWriter = new JsonMapObjectReaderWriter();
    private Pattern samlRolesSeparatorPattern;

    AuthTokenProcessorHandler(Settings settings, Settings jwtSettings, Saml2SettingsProvider saml2SettingsProvider)
            throws Exception {
        this.saml2SettingsProvider = saml2SettingsProvider;

        this.jwtRolesKey = jwtSettings.get("roles_key", "roles");
        this.jwtSubjectKey = jwtSettings.get("subject_key", "sub");

        this.samlRolesKey = settings.get("roles_key");
        this.samlSubjectKey = settings.get("subject_key");
        // Originally release with a typo, prioritize correct spelling over typo'ed version
        String samlRolesSeparator = settings.get("roles_separator", settings.get("roles_seperator"));
        this.kibanaRootUrl = settings.get("kibana_url");
        if (samlRolesSeparator != null) {
            this.samlRolesSeparatorPattern = Pattern.compile(samlRolesSeparator);
        }

        if (samlRolesKey == null || samlRolesKey.length() == 0) {
            log.warn("roles_key is not configured, will only extract subject from SAML");
            samlRolesKey = null;
        }

        if (samlSubjectKey == null || samlSubjectKey.length() == 0) {
            // If subjectKey == null, get subject from the NameID element.
            // Thus, this is a valid configuration.
            samlSubjectKey = null;
        }

        if (samlRolesSeparator == null || samlRolesSeparator.length() == 0) {
            samlRolesSeparator = null;
        }

        this.initJwtExpirySettings(settings);
        this.signingKey = this.createJwkFromSettings(settings, jwtSettings);

        this.jwtProducer = new JoseJwtProducer();
        this.jwtProducer.setSignatureProvider(JwsUtils.getSignatureProvider(this.signingKey));

    }

    @SuppressWarnings("removal")
    boolean handle(RestRequest restRequest, RestChannel restChannel) throws Exception {
        try {
            final SecurityManager sm = System.getSecurityManager();

            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            return AccessController.doPrivileged(new PrivilegedExceptionAction<Boolean>() {
                @Override
                public Boolean run() throws XPathExpressionException, SamlConfigException, IOException,
                        ParserConfigurationException, SAXException, SettingsException {
                    return handleLowLevel(restRequest, restChannel);
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    private AuthTokenProcessorAction.Response handleImpl(RestRequest restRequest, RestChannel restChannel,
            String samlResponseBase64, String samlRequestId, String acsEndpoint, Saml2Settings saml2Settings)
            throws XPathExpressionException, ParserConfigurationException, SAXException, IOException,
            SettingsException {
        if (token_log.isDebugEnabled()) {
            try {
                token_log.debug("SAMLResponse for {}\n{}", samlRequestId, new String(Util.base64decoder(samlResponseBase64), StandardCharsets.UTF_8));
            } catch (Exception e) {
                token_log.warn(
                        "SAMLResponse for {} cannot be decoded from base64\n{}",
                        samlRequestId, samlResponseBase64, e);
            }
        }

        try {

            SamlResponse samlResponse = new SamlResponse(saml2Settings, null);
            samlResponse.setDestinationUrl(acsEndpoint);
            samlResponse.loadXmlFromBase64(samlResponseBase64);

            if (!samlResponse.isValid(samlRequestId)) {
                log.warn("Error while validating SAML response in /_opendistro/_security/api/authtoken");
                return null;
            }

            AuthTokenProcessorAction.Response responseBody = new AuthTokenProcessorAction.Response();
            responseBody.setAuthorization("bearer " + this.createJwt(samlResponse));

            return responseBody;
        } catch (ValidationError e) {
            log.warn("Error while validating SAML response", e);
            return null;
        } catch (Exception e) {
            log.error("Error while converting SAML to JWT", e);
            return null;
        }
    }

    private boolean handleLowLevel(RestRequest restRequest, RestChannel restChannel) throws SamlConfigException,
            IOException, XPathExpressionException, ParserConfigurationException, SAXException, SettingsException {
        try {

            if (restRequest.getXContentType() != XContentType.JSON) {
                throw new OpenSearchSecurityException(
                        "/_opendistro/_security/api/authtoken expects content with type application/json",
                        RestStatus.UNSUPPORTED_MEDIA_TYPE);

            }

            if (restRequest.method() != Method.POST) {
                throw new OpenSearchSecurityException("/_opendistro/_security/api/authtoken expects POST requests",
                        RestStatus.METHOD_NOT_ALLOWED);
            }

            Saml2Settings saml2Settings = this.saml2SettingsProvider.getCached();

            BytesReference bytesReference = restRequest.requiredContent();

            JsonNode jsonRoot = DefaultObjectMapper.objectMapper.readTree(BytesReference.toBytes(bytesReference));

            if (!(jsonRoot instanceof ObjectNode)) {
                throw new JsonParseException(null, "Unexpected json format: " + jsonRoot);
            }

            if (((ObjectNode) jsonRoot).get("SAMLResponse") == null) {
                log.warn("SAMLResponse is missing from request ");

                throw new OpenSearchSecurityException("SAMLResponse is missing from request",
                        RestStatus.BAD_REQUEST);

            }

            String samlResponseBase64 = ((ObjectNode) jsonRoot).get("SAMLResponse").asText();
            String samlRequestId = ((ObjectNode) jsonRoot).get("RequestId") != null
                    ? ((ObjectNode) jsonRoot).get("RequestId").textValue()
                    : null;
            String acsEndpoint = saml2Settings.getSpAssertionConsumerServiceUrl().toString();

            if (((ObjectNode) jsonRoot).get("acsEndpoint") != null
                    && ((ObjectNode) jsonRoot).get("acsEndpoint").textValue() != null) {
                acsEndpoint = getAbsoluteAcsEndpoint(((ObjectNode) jsonRoot).get("acsEndpoint").textValue());
            }

            AuthTokenProcessorAction.Response responseBody = this.handleImpl(restRequest, restChannel,
                    samlResponseBase64, samlRequestId, acsEndpoint, saml2Settings);

            if (responseBody == null) {
                return false;
            }

            String responseBodyString = DefaultObjectMapper.objectMapper.writeValueAsString(responseBody);

            BytesRestResponse authenticateResponse = new BytesRestResponse(RestStatus.OK, "application/json",
                    responseBodyString);
            restChannel.sendResponse(authenticateResponse);

            return true;
        } catch (JsonProcessingException e) {
            log.warn("Error while parsing JSON for /_opendistro/_security/api/authtoken", e);

            BytesRestResponse authenticateResponse = new BytesRestResponse(RestStatus.BAD_REQUEST,
                    "JSON could not be parsed");
            restChannel.sendResponse(authenticateResponse);
            return true;
        }
    }

    JsonWebKey createJwkFromSettings(Settings settings, Settings jwtSettings) throws Exception {

        String exchangeKey = settings.get("exchange_key");

        if (!Strings.isNullOrEmpty(exchangeKey)) {

            JsonWebKey jwk = new JsonWebKey();

            jwk.setKeyType(KeyType.OCTET);
            jwk.setAlgorithm("HS512");
            jwk.setPublicKeyUse(PublicKeyUse.SIGN);
            jwk.setProperty("k", exchangeKey);

            return jwk;
        } else {

            Settings jwkSettings = jwtSettings.getAsSettings("key");

            if (jwkSettings.isEmpty()) {
                throw new Exception(
                        "Settings for key exchange missing. Please specify at least the option exchange_key with a shared secret.");
            }

            JsonWebKey jwk = new JsonWebKey();

            for (String key : jwkSettings.keySet()) {
                jwk.setProperty(key, jwkSettings.get(key));
            }

            return jwk;
        }
    }

    private String createJwt(SamlResponse samlResponse) throws Exception {
        JwtClaims jwtClaims = new JwtClaims();
        JwtToken jwt = new JwtToken(jwtClaims);

        jwtClaims.setNotBefore(System.currentTimeMillis() / 1000);
        jwtClaims.setExpiryTime(getJwtExpiration(samlResponse));

        jwtClaims.setProperty(this.jwtSubjectKey, this.extractSubject(samlResponse));

        if (this.samlSubjectKey != null) {
            jwtClaims.setProperty("saml_ni", samlResponse.getNameId());
        }

        if (samlResponse.getNameIdFormat() != null) {
            jwtClaims.setProperty("saml_nif", SamlNameIdFormat.getByUri(samlResponse.getNameIdFormat()).getShortName());
        }

        String sessionIndex = samlResponse.getSessionIndex();

        if (sessionIndex != null) {
            jwtClaims.setProperty("saml_si", sessionIndex);
        }

        if (this.samlRolesKey != null && this.jwtRolesKey != null) {
            String[] roles = this.extractRoles(samlResponse);

            jwtClaims.setProperty(this.jwtRolesKey, roles);
        }

        String encodedJwt = this.jwtProducer.processJwt(jwt);

        if (token_log.isDebugEnabled()) {
            token_log.debug("Created JWT: " + encodedJwt + "\n" + jsonMapReaderWriter.toJson(jwt.getJwsHeaders()) + "\n"
                    + JwtUtils.claimsToJson(jwt.getClaims()));
        }

        return encodedJwt;
    }

    private long getJwtExpiration(SamlResponse samlResponse) throws Exception {
        DateTime sessionNotOnOrAfter = samlResponse.getSessionNotOnOrAfter();

        if (this.expiryBaseValue == ExpiryBaseValue.NOW) {
            return System.currentTimeMillis() / 1000 + this.expiryOffset;
        } else if (this.expiryBaseValue == ExpiryBaseValue.SESSION) {
            if (sessionNotOnOrAfter != null) {
                return sessionNotOnOrAfter.getMillis() / 1000 + this.expiryOffset;
            } else {
                throw new Exception(
                        "Error while determining JWT expiration time: SamlResponse did not contain sessionNotOnOrAfter value");
            }
        } else {
            // AUTO

            if (sessionNotOnOrAfter != null) {
                return sessionNotOnOrAfter.getMillis() / 1000;
            } else {
                return System.currentTimeMillis() / 1000 + (this.expiryOffset > 0 ? this.expiryOffset : 60 * 60);
            }
        }
    }

    private void initJwtExpirySettings(Settings settings) {
        String expiry = settings.get("jwt.expiry");

        if (Strings.isNullOrEmpty(expiry)) {
            return;
        }

        Matcher matcher = EXPIRY_SETTINGS_PATTERN.matcher(expiry);

        if (!matcher.matches()) {
            log.error("Invalid value for jwt.expiry: {}; using defaults.", expiry);
            return;
        }

        String baseValue = matcher.group(1);
        String offset = matcher.group(2);

        if (offset != null && !StringUtils.isNumeric(offset)) {
            log.error("Invalid offset value for jwt.expiry: {}; using defaults.", expiry);
            return;
        }

        if (!Strings.isNullOrEmpty(baseValue)) {
            try {
                this.expiryBaseValue = ExpiryBaseValue.valueOf(baseValue.toUpperCase());
            } catch (IllegalArgumentException e) {
                log.error("Invalid base value for jwt.expiry: {}; using defaults", expiry);
                return;
            }
        }

        if (offset != null) {
            this.expiryOffset = Integer.parseInt(offset) * 60;
        }
    }

    private String extractSubject(SamlResponse samlResponse) throws Exception {
        if (this.samlSubjectKey == null) {
            return samlResponse.getNameId();
        }

        List<String> values = samlResponse.getAttributes().get(this.samlSubjectKey);

        if (values == null || values.size() == 0) {
            return null;
        }

        return values.get(0);
    }

    private String[] extractRoles(SamlResponse samlResponse) throws XPathExpressionException, ValidationError {
        if (this.samlRolesKey == null) {
            return new String[0];
        }

        List<String> values = samlResponse.getAttributes().get(this.samlRolesKey);

        if (values == null || values.size() == 0) {
            return null;
        }

        if (samlRolesSeparatorPattern != null) {
            values = splitRoles(values);
        }

        return values.toArray(new String[values.size()]);
    }

    private List<String> splitRoles(List<String> values) {
        return values.stream()
                .flatMap(v -> samlRolesSeparatorPattern.splitAsStream(v))
                .filter(r -> !Strings.isNullOrEmpty(r))
                .collect(Collectors.toList());
    }

    private String getAbsoluteAcsEndpoint(String acsEndpoint) {
        try {
            URI acsEndpointUri = new URI(acsEndpoint);

            if (acsEndpointUri.isAbsolute()) {
                return acsEndpoint;
            } else {
                return new URI(this.kibanaRootUrl).resolve(acsEndpointUri).toString();
            }
        } catch (URISyntaxException e) {
            log.error("Could not parse URI for acsEndpoint: {}", acsEndpoint);
            return acsEndpoint;
        }
    }

    private enum ExpiryBaseValue {
        AUTO, NOW, SESSION
    }

    public JsonWebKey getSigningKey() {
        return signingKey;
    }
}
