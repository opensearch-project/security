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

package com.amazon.dlic.auth.http.jwt.keybyoidc;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.user.AuthCredentials;

import com.amazon.dlic.auth.http.jwt.AbstractHTTPJwtAuthenticator;
import com.amazon.dlic.util.SettingsBasedSSLConfigurator;
import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;

import static org.apache.hc.core5.http.HttpHeaders.AUTHORIZATION;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.CLIENT_ID;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.ISSUER_ID_URL;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.SUB_CLAIM;

public class HTTPOpenIdAuthenticator implements HTTPAuthenticator {

    private final static Logger log = LogManager.getLogger(HTTPOpenIdAuthenticator.class);
    private final Settings settings;
    private final Path configPath;
    private final int requestTimeoutMs = 10000;
    private final SettingsBasedSSLConfigurator.SSLConfig sslConfig;
    private final String userInfoEndpoint;
    private volatile HTTPJwtKeyByOpenIdConnectAuthenticator openIdJwtAuthenticator;

    public HTTPOpenIdAuthenticator(Settings settings, Path configPath) throws Exception {
        this.settings = settings;
        this.configPath = configPath;
        this.sslConfig = getSSLConfig(settings, configPath);
        userInfoEndpoint = settings.get("userinfo_endpoint");
        openIdJwtAuthenticator = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, configPath);
    }

    public HTTPJwtKeyByOpenIdConnectAuthenticator getOpenIdJwtAuthenticator() {
        return openIdJwtAuthenticator;
    }

    public String getType() {
        return "oidc";
    }

    private static SettingsBasedSSLConfigurator.SSLConfig getSSLConfig(Settings settings, Path configPath) throws Exception {
        return new SettingsBasedSSLConfigurator(settings, configPath, "openid_connect_idp").buildSSLConfig();
    }

    @Override
    public AuthCredentials extractCredentials(SecurityRequest request, ThreadContext context) throws OpenSearchSecurityException {
        if (this.userInfoEndpoint != null && !this.userInfoEndpoint.isBlank()) {
            return extractCredentials0(request, context);
        }
        return (this.openIdJwtAuthenticator.extractCredentials(request, context));
    }

    @Override
    public Optional<SecurityResponse> reRequestAuthentication(SecurityRequest request, AuthCredentials credentials) {
        return Optional.empty();
    }

    /**
     * This method performs the logic required for making use of the userinfo_endpoint OIDC feature.
     * Per the spec: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo there are 10 verification steps we must perform
     * 1. Validate the OP is correct via TLS certificate check
     * 2. Validate response is OK
     * 3. Validate application type is either JSON or JWT
     * 4. Validate response is one of: just signed, just encrypted, or signed then encrypted (encryption MUST NOT occur before signing)
     * 5. If response is signed then validate the signature via JWS and confirm the response has "iss" and "aud" claims
     * 6. Validate "iss" claim is equal to the issuer ID url
     * 7. Validate the "aud" claim is equal to the client ID
     * 8. If the client provides a userinfo_encrypted_response_alg value decrypt the response using the keys from registration
     * 9. Validate "sub" claim is always present
     * 10. Validate "sub" claim matches the ID token
     * @param request The SecurityRequest to perform auth on
     * @param context The active thread context
     * @return AuthCredentials formed through querying the userinfo_endpoint
     * @throws OpenSearchSecurityException On failure to extract credentials from the request
     */
    public AuthCredentials extractCredentials0(SecurityRequest request, ThreadContext context) throws OpenSearchSecurityException {

        try {

            URI userInfoEndpointURI = new URI(this.userInfoEndpoint);

            String bearerHeader = AbstractHTTPJwtAuthenticator.getJwtTokenString(request, AUTHORIZATION, null, false);

            HTTPResponse httpResponse = getHttpResponse(bearerHeader, userInfoEndpointURI);

            try {

                UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);

                if (!userInfoResponse.indicatesSuccess()) {
                    throw new AuthenticatorUnavailableException(
                        "Error while getting " + this.userInfoEndpoint + ": " + userInfoResponse.toErrorResponse()
                    );
                }

                UserInfoSuccessResponse userInfoSuccessResponse = userInfoResponse.toSuccessResponse();

                String contentType = userInfoSuccessResponse.getEntityContentType().getType();

                JWTClaimsSet claims;
                boolean isSigned = contentType.contains(ContentType.APPLICATION_JWT.getType());
                if (isSigned) { // We don't need the userinfo_encrypted_response_alg since the
                    // selfRefreshingKeyProvider has access to the keys
                    claims = openIdJwtAuthenticator.getJwtClaimsSetFromInfoContent(
                        userInfoSuccessResponse.getUserInfoJWT().getParsedString()
                    );
                } else {
                    claims = JWTClaimsSet.parse(userInfoSuccessResponse.getUserInfo().toString());
                }

                String id = openIdJwtAuthenticator.getJwtClaimsSet(request).getSubject();
                String missing = validateResponseClaims(claims, id, isSigned);
                if (!missing.isBlank()) {
                    throw new AuthenticatorUnavailableException(
                        "Error while getting " + this.userInfoEndpoint + ": Missing or invalid required claims in response: " + missing
                    );
                }

                final String subject = openIdJwtAuthenticator.extractSubject(claims);
                if (subject == null) {
                    log.error("No subject found in JWT token");
                    return null;
                }

                final String[] roles = openIdJwtAuthenticator.extractRoles(claims);

                AuthCredentials ac = new AuthCredentials(subject, roles);

                for (Map.Entry<String, Object> claim : claims.getClaims().entrySet()) {
                    ac.addAttribute("attr.jwt." + claim.getKey(), String.valueOf(claim.getValue()));
                }

                return ac.markComplete();
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        } catch (IOException | URISyntaxException | com.nimbusds.oauth2.sdk.ParseException e) {
            throw new AuthenticatorUnavailableException("Error while getting " + this.userInfoEndpoint + ": " + e, e);
        }
    }

    private HTTPResponse getHttpResponse(String bearerHeader, URI userInfoEndpointURI) throws IOException {
        BearerAccessToken accessToken = new BearerAccessToken(bearerHeader);

        UserInfoRequest userInfoRequest = new UserInfoRequest(userInfoEndpointURI, accessToken);

        HTTPRequest httpRequest = userInfoRequest.toHTTPRequest();

        HTTPResponse httpResponse = httpRequest.send();
        if (httpResponse.getStatusCode() < 200 || httpResponse.getStatusCode() >= 300) {
            throw new AuthenticatorUnavailableException(
                "Error while getting " + this.userInfoEndpoint + ": " + httpResponse.getStatusMessage()
            );
        }
        return httpResponse;
    }

    private String validateResponseClaims(JWTClaimsSet claims, String id, boolean isSigned) {

        StringBuilder missing = new StringBuilder();

        if (claims.getClaim(SUB_CLAIM) == null || claims.getClaim(SUB_CLAIM).toString().isBlank() || !claims.getClaim("sub").equals(id)) {
            missing = missing.append(SUB_CLAIM);
        }

        if (isSigned) {
            if (claims.getIssuer() == null || claims.getIssuer().isBlank() || !claims.getIssuer().equals(settings.get(ISSUER_ID_URL))) {
                missing = missing.append("iss");
            }
            if (claims.getAudience() == null
                || claims.getAudience().toString().isBlank()
                || !claims.getAudience().contains(settings.get(CLIENT_ID))) {
                missing = missing.append("aud");
            }
        }

        return missing.toString();
    }

    private final class HTTPJwtKeyByOpenIdConnectAuthenticator extends AbstractHTTPJwtAuthenticator {

        public HTTPJwtKeyByOpenIdConnectAuthenticator(Settings settings, Path configPath) {
            super(settings, configPath);
        }

        protected KeyProvider initKeyProvider(Settings settings, Path configPath) throws Exception {
            int idpRequestTimeoutMs = settings.getAsInt("idp_request_timeout_ms", 5000);
            int idpQueuedThreadTimeoutMs = settings.getAsInt("idp_queued_thread_timeout_ms", 2500);

            int refreshRateLimitTimeWindowMs = settings.getAsInt("refresh_rate_limit_time_window_ms", 10000);
            int refreshRateLimitCount = settings.getAsInt("refresh_rate_limit_count", 10);
            String jwksUri = settings.get("jwks_uri");
            KeySetRetriever keySetRetriever;

            if (jwksUri != null && !jwksUri.isBlank()) {
                keySetRetriever = new KeySetRetriever(
                    getSSLConfig(settings, configPath),
                    settings.getAsBoolean("cache_jwks_endpoint", false),
                    jwksUri
                );
            } else {
                keySetRetriever = new KeySetRetriever(
                    settings.get("openid_connect_url"),
                    getSSLConfig(settings, configPath),
                    settings.getAsBoolean("cache_jwks_endpoint", false)
                );
            }

            keySetRetriever.setRequestTimeoutMs(idpRequestTimeoutMs);

            SelfRefreshingKeySet selfRefreshingKeySet = new SelfRefreshingKeySet(keySetRetriever);

            selfRefreshingKeySet.setRequestTimeoutMs(idpRequestTimeoutMs);
            selfRefreshingKeySet.setQueuedThreadTimeoutMs(idpQueuedThreadTimeoutMs);
            selfRefreshingKeySet.setRefreshRateLimitTimeWindowMs(refreshRateLimitTimeWindowMs);
            selfRefreshingKeySet.setRefreshRateLimitCount(refreshRateLimitCount);

            return selfRefreshingKeySet;
        }

        private JWTClaimsSet getJwtClaimsSet(SecurityRequest request) throws OpenSearchSecurityException {
            String parsedToken = getJwtTokenString(request, jwtHeaderName, jwtUrlParameter, isDefaultAuthHeader);
            return getJwtClaimsSetFromInfoContent(parsedToken);
        }

        private JWTClaimsSet getJwtClaimsSetFromInfoContent(String userInfoContent) throws OpenSearchSecurityException {
            SignedJWT jwt;
            JWTClaimsSet claimsSet;
            try {
                jwt = super.jwtVerifier.getVerifiedJwtToken(userInfoContent);
                claimsSet = jwt.getJWTClaimsSet();
            } catch (OpenSearchSecurityException | ParseException | BadCredentialsException e) {
                throw new RuntimeException(e);
            }
            return claimsSet;
        }

        @Override
        public AuthCredentials extractCredentials(SecurityRequest request, ThreadContext context) throws OpenSearchSecurityException {
            return super.extractCredentials(request, context);
        }

        @Override
        public String getType() {
            return "jwt-key-by-oidc";
        }
    }
}
