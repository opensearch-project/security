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
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.xml.xpath.XPathExpressionException;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.api.AuthTokenProcessorAction;
import org.opensearch.security.filter.SecurityResponse;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.exception.ValidationError;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.util.Util;
import org.joda.time.DateTime;

import static org.opensearch.security.authtoken.jwt.KeyPaddingUtil.padSecret;

class AuthTokenProcessorHandler {
    private static final Logger log = LogManager.getLogger(AuthTokenProcessorHandler.class);
    private static final Logger token_log = LogManager.getLogger("com.amazon.dlic.auth.http.saml.Token");
    private static final Pattern EXPIRY_SETTINGS_PATTERN = Pattern.compile("\\s*(\\w+)\\s*(?:\\+\\s*(\\w+))?\\s*");

    private Saml2SettingsProvider saml2SettingsProvider;
    private String jwtSubjectKey;
    private String jwtRolesKey;
    private String samlSubjectKey;
    private String samlRolesKey;
    private String kibanaRootUrl;

    private long expiryOffset = 0;
    private ExpiryBaseValue expiryBaseValue = ExpiryBaseValue.AUTO;
    private JWK signingKey;
    private JWSHeader jwsHeader;
    private Pattern samlRolesSeparatorPattern;

    AuthTokenProcessorHandler(Settings settings, Settings jwtSettings, Saml2SettingsProvider saml2SettingsProvider) throws Exception {
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

        if (samlRolesKey == null || samlRolesKey.isEmpty()) {
            log.warn("roles_key is not configured, will only extract subject from SAML");
            samlRolesKey = null;
        }

        if (samlSubjectKey == null || samlSubjectKey.isEmpty()) {
            // If subjectKey == null, get subject from the NameID element.
            // Thus, this is a valid configuration.
            samlSubjectKey = null;
        }

        this.initJwtExpirySettings(settings);
        this.signingKey = this.createJwkFromSettings(settings, jwtSettings);
        this.jwsHeader = this.createJwsHeaderFromSettings();
    }

    @SuppressWarnings("removal")
    Optional<SecurityResponse> handle(RestRequest restRequest) throws Exception {
        try {
            final SecurityManager sm = System.getSecurityManager();

            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            return AccessController.doPrivileged((PrivilegedExceptionAction<Optional<SecurityResponse>>) () -> handleLowLevel(restRequest));
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    private AuthTokenProcessorAction.Response handleImpl(
        String samlResponseBase64,
        String samlRequestId,
        String acsEndpoint,
        Saml2Settings saml2Settings,
        String requestPath // the parameter will be removed in the future as soon as we will read of legacy paths aka
                           // /_opendistro/_security/...
    ) {
        if (token_log.isDebugEnabled()) {
            try {
                token_log.debug(
                    "SAMLResponse for {}\n{}",
                    samlRequestId,
                    new String(Util.base64decoder(samlResponseBase64), StandardCharsets.UTF_8)
                );
            } catch (Exception e) {
                token_log.warn("SAMLResponse for {} cannot be decoded from base64\n{}", samlRequestId, samlResponseBase64, e);
            }
        }

        try {

            SamlResponse samlResponse = new SamlResponse(saml2Settings, acsEndpoint, samlResponseBase64);

            if (!samlResponse.isValid(samlRequestId)) {
                log.warn("Error while validating SAML response in {}", requestPath);
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

    private Optional<SecurityResponse> handleLowLevel(RestRequest restRequest) throws SamlConfigException, IOException {
        try {

            if (restRequest.getMediaType() != XContentType.JSON) {
                throw new OpenSearchSecurityException(
                    restRequest.path() + " expects content with type application/json",
                    RestStatus.UNSUPPORTED_MEDIA_TYPE
                );

            }

            if (restRequest.method() != Method.POST) {
                throw new OpenSearchSecurityException(restRequest.path() + " expects POST requests", RestStatus.METHOD_NOT_ALLOWED);
            }

            Saml2Settings saml2Settings = this.saml2SettingsProvider.getCached();

            BytesReference bytesReference = restRequest.requiredContent();

            JsonNode jsonRoot = DefaultObjectMapper.objectMapper.readTree(BytesReference.toBytes(bytesReference));

            if (!(jsonRoot instanceof ObjectNode)) {
                throw new JsonParseException(null, "Unexpected json format: " + jsonRoot);
            }

            if (((ObjectNode) jsonRoot).get("SAMLResponse") == null) {
                log.warn("SAMLResponse is missing from request ");

                throw new OpenSearchSecurityException("SAMLResponse is missing from request", RestStatus.BAD_REQUEST);

            }

            String samlResponseBase64 = ((ObjectNode) jsonRoot).get("SAMLResponse").asText();
            String samlRequestId = ((ObjectNode) jsonRoot).get("RequestId") != null
                ? ((ObjectNode) jsonRoot).get("RequestId").textValue()
                : null;
            String acsEndpoint = saml2Settings.getSpAssertionConsumerServiceUrl().toString();

            if (((ObjectNode) jsonRoot).get("acsEndpoint") != null && ((ObjectNode) jsonRoot).get("acsEndpoint").textValue() != null) {
                acsEndpoint = getAbsoluteAcsEndpoint(((ObjectNode) jsonRoot).get("acsEndpoint").textValue());
            }

            AuthTokenProcessorAction.Response responseBody = this.handleImpl(
                samlResponseBase64,
                samlRequestId,
                acsEndpoint,
                saml2Settings,
                restRequest.path()
            );

            if (responseBody == null) {
                return Optional.empty();
            }

            String responseBodyString = DefaultObjectMapper.objectMapper.writeValueAsString(responseBody);

            return Optional.of(new SecurityResponse(HttpStatus.SC_OK, null, responseBodyString, XContentType.JSON.mediaType()));
        } catch (JsonProcessingException e) {
            log.warn("Error while parsing JSON for {}", restRequest.path(), e);
            return Optional.of(new SecurityResponse(HttpStatus.SC_BAD_REQUEST, "JSON could not be parsed"));
        }
    }

    private JWSHeader createJwsHeaderFromSettings() {
        JWSHeader.Builder jwsHeaderBuilder = new JWSHeader.Builder(JWSAlgorithm.HS512);
        return jwsHeaderBuilder.build();
    }

    JWK createJwkFromSettings(Settings settings, Settings jwtSettings) throws Exception {
        String exchangeKey = settings.get("exchange_key");

        if (!Strings.isNullOrEmpty(exchangeKey)) {
            exchangeKey = padSecret(new String(Base64.getUrlDecoder().decode(exchangeKey), StandardCharsets.UTF_8), JWSAlgorithm.HS512);

            return new OctetSequenceKey.Builder(exchangeKey.getBytes(StandardCharsets.UTF_8)).algorithm(JWSAlgorithm.HS512)
                .keyUse(KeyUse.SIGNATURE)
                .build();
        } else {
            Settings jwkSettings = jwtSettings.getAsSettings("key");

            if (!jwkSettings.hasValue("k") && !Strings.isNullOrEmpty(jwkSettings.get("k"))) {
                throw new Exception(
                    "Settings for key exchange missing. Please specify at least the option exchange_key with a shared secret."
                );
            }

            String k = padSecret(
                new String(Base64.getUrlDecoder().decode(jwkSettings.get("k")), StandardCharsets.UTF_8),
                JWSAlgorithm.HS512
            );

            return new OctetSequenceKey.Builder(k.getBytes(StandardCharsets.UTF_8)).algorithm(JWSAlgorithm.HS512)
                .keyUse(KeyUse.SIGNATURE)
                .build();
        }
    }

    private String createJwt(SamlResponse samlResponse) throws Exception {
        JWTClaimsSet.Builder jwtClaimsBuilder = new JWTClaimsSet.Builder().notBeforeTime(new Date())
            .expirationTime(new Date(getJwtExpiration(samlResponse)))
            .claim(this.jwtSubjectKey, this.extractSubject(samlResponse));

        if (this.samlSubjectKey != null) {
            jwtClaimsBuilder.claim("saml_ni", samlResponse.getNameId());
        }
        if (samlResponse.getNameIdFormat() != null) {
            jwtClaimsBuilder.claim("saml_nif", SamlNameIdFormat.getByUri(samlResponse.getNameIdFormat()).getShortName());
        }

        String sessionIndex = samlResponse.getSessionIndex();

        if (sessionIndex != null) {
            jwtClaimsBuilder.claim("saml_si", sessionIndex);
        }

        if (this.samlRolesKey != null && this.jwtRolesKey != null) {
            String[] roles = this.extractRoles(samlResponse);

            jwtClaimsBuilder.claim(this.jwtRolesKey, roles);
        }
        JWTClaimsSet jwtClaims = jwtClaimsBuilder.build();
        SignedJWT jwt = new SignedJWT(this.jwsHeader, jwtClaims);
        jwt.sign(new DefaultJWSSignerFactory().createJWSSigner(this.signingKey));

        String encodedJwt = jwt.serialize();

        if (token_log.isDebugEnabled()) {
            token_log.debug("Created JWT: " + encodedJwt + "\n" + jwt.getHeader().toString() + "\n" + jwt.getJWTClaimsSet().toString());
        }

        return encodedJwt;
    }

    private long getJwtExpiration(SamlResponse samlResponse) throws Exception {
        DateTime sessionNotOnOrAfter = samlResponse.getSessionNotOnOrAfter();

        if (this.expiryBaseValue == ExpiryBaseValue.NOW) {
            return System.currentTimeMillis() + this.expiryOffset * 1000;
        } else if (this.expiryBaseValue == ExpiryBaseValue.SESSION) {
            if (sessionNotOnOrAfter != null) {
                return sessionNotOnOrAfter.getMillis() + this.expiryOffset * 1000;
            } else {
                throw new Exception("Error while determining JWT expiration time: SamlResponse did not contain sessionNotOnOrAfter value");
            }
        } else {
            // AUTO

            if (sessionNotOnOrAfter != null) {
                return sessionNotOnOrAfter.getMillis();
            } else {
                return System.currentTimeMillis() + (this.expiryOffset > 0 ? this.expiryOffset * 1000 : 60 * 60_000);
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
        AUTO,
        NOW,
        SESSION
    }

    public JWK getSigningKey() {
        return signingKey;
    }
}
