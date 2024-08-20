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
import java.nio.file.Path;
import java.text.ParseException;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.core5.http.HttpEntity;
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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.APPLICATION_JSON;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.APPLICATION_JWT;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.AUTHORIZATION_HEADER;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.CLIENT_ID;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.ISSUER_ID_URL;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.SUB_CLAIM;

public class HTTPOpenIdAuthenticator implements HTTPAuthenticator {

    private final static Logger log = LogManager.getLogger(HTTPOpenIdAuthenticator.class);
    private final Settings settings;
    private final Path configPath;
    private final int requestTimeoutMs = 10000;
    private final SettingsBasedSSLConfigurator.SSLConfig sslConfig;
    private final String userinfo_endpoint;
    private volatile HTTPJwtKeyByOpenIdConnectAuthenticator openIdJwtAuthenticator;

    public HTTPOpenIdAuthenticator(Settings settings, Path configPath) throws Exception {
        this.settings = settings;
        this.configPath = configPath;
        this.sslConfig = getSSLConfig(settings, configPath);
        userinfo_endpoint = settings.get("userinfo_endpoint");
        openIdJwtAuthenticator = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, configPath);
    }

    public HTTPJwtKeyByOpenIdConnectAuthenticator getOpenIdJwtAuthenticator() {
        if (openIdJwtAuthenticator == null) {
            synchronized (this) {
                if (openIdJwtAuthenticator == null) {
                    openIdJwtAuthenticator = new HTTPJwtKeyByOpenIdConnectAuthenticator(settings, configPath);
                }
            }
        }
        return openIdJwtAuthenticator;
    }

    public String getType() {
        return null;
    }

    private static SettingsBasedSSLConfigurator.SSLConfig getSSLConfig(Settings settings, Path configPath) throws Exception {
        return new SettingsBasedSSLConfigurator(settings, configPath, "openid_connect_idp").buildSSLConfig();
    }

    @Override
    public AuthCredentials extractCredentials(SecurityRequest request, ThreadContext context) throws OpenSearchSecurityException {
        if (this.userinfo_endpoint != null && !this.userinfo_endpoint.isBlank()) {
            return extractCredentials0(request, context);
        }
        return (this.openIdJwtAuthenticator.extractCredentials(request, context));
    }

    @Override
    public Optional<SecurityResponse> reRequestAuthentication(SecurityRequest request, AuthCredentials credentials) {
        return Optional.empty();
    }

    // Public for testing
    public CloseableHttpClient createHttpClient() {
        HttpClientBuilder builder;
        builder = HttpClients.custom();
        builder.useSystemProperties();
        if (sslConfig != null) {
            final HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory())
                .build();

            builder.setConnectionManager(cm);
        }

        return builder.build();
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

        try (CloseableHttpClient httpClient = createHttpClient()) {

            HttpGet httpGet = new HttpGet(this.userinfo_endpoint);

            RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(requestTimeoutMs, TimeUnit.MILLISECONDS)
                .setConnectTimeout(requestTimeoutMs, TimeUnit.MILLISECONDS)
                .build();

            httpGet.setConfig(requestConfig);
            httpGet.addHeader(AUTHORIZATION_HEADER, request.getHeaders().get(AUTHORIZATION_HEADER));

            // HTTPGet should internally verify the appropriate TLS cert.

            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {

                if (response.getCode() < 200 || response.getCode() >= 300) {
                    throw new AuthenticatorUnavailableException(
                        "Error while getting " + this.userinfo_endpoint + ": " + response.getReasonPhrase()
                    );
                }

                HttpEntity httpEntity = response.getEntity();

                if (httpEntity == null) {
                    throw new AuthenticatorUnavailableException(
                        "Error while getting " + this.userinfo_endpoint + ": Empty response entity"
                    );
                }

                String contentType = httpEntity.getContentType();

                if (!contentType.equals(APPLICATION_JSON) && !contentType.equals(APPLICATION_JWT)) {
                    throw new AuthenticatorUnavailableException(
                        "Error while getting " + this.userinfo_endpoint + ": Invalid content type in response"
                    );
                }

                String userinfoContent = httpEntity.getContent().toString();
                JWTClaimsSet claims;
                boolean isSigned = contentType.equals(APPLICATION_JWT);
                if (contentType.equals(APPLICATION_JWT)) { // We don't need the userinfo_encrypted_response_alg since the
                                                           // selfRefreshingKeyProvider has access to the keys
                    claims = openIdJwtAuthenticator.getJwtClaimsSetFromInfoContent(userinfoContent);
                } else {
                    claims = JWTClaimsSet.parse(userinfoContent);
                }

                String id = openIdJwtAuthenticator.getJwtClaimsSet(request).getSubject();

                String missing = validateResponseClaims(claims, id, isSigned);
                if (!missing.isBlank()) {
                    throw new AuthenticatorUnavailableException(
                        "Error while getting " + this.userinfo_endpoint + ": Missing or invalid required claims in response: " + missing
                    );
                }

                final String subject = openIdJwtAuthenticator.extractSubject(claims);
                if (subject == null) {
                    log.error("No subject found in JWT token");
                    return null;
                }

                final String[] roles = openIdJwtAuthenticator.extractRoles(claims);
                return new AuthCredentials(subject, roles).markComplete();
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        } catch (IOException e) {
            throw new AuthenticatorUnavailableException("Error while getting " + this.userinfo_endpoint + ": " + e, e);
        }
    }

    private String validateResponseClaims(JWTClaimsSet claims, String id, boolean isSigned) {

        String missing = "";

        if (claims.getClaim(SUB_CLAIM) == null || claims.getClaim(SUB_CLAIM).toString().isBlank() || !claims.getClaim("sub").equals(id)) {
            missing = missing.concat(SUB_CLAIM);
        }

        if (isSigned) {
            if (claims.getClaim("iss") == null
                || claims.getClaim("iss").toString().isBlank()
                || !claims.getClaim("iss").toString().equals(settings.get(ISSUER_ID_URL))) {
                missing = missing.concat("iss");
            }
            if (claims.getClaim("aud") == null
                || claims.getClaim("aud").toString().isBlank()
                || !claims.getClaim("aud").toString().equals(settings.get(CLIENT_ID))) {
                missing = missing.concat("aud");
            }
        }

        return missing;
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
            String parsedToken = super.getJwtTokenString(request);
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
