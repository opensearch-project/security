package com.amazon.dlic.auth.http.jwt.keybyoidc;

import com.amazon.dlic.auth.http.jwt.AbstractHTTPJwtAuthenticator;
import com.amazon.dlic.util.SettingsBasedSSLConfigurator;
import com.google.googlejavaformat.Op;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.Claims;
import org.apache.hc.client5.http.cache.HttpCacheStorage;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.cache.CachingHttpClients;
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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.APPLICATION_JSON;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.APPLICATION_JWT;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.AUTHORIZATION_HEADER;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.CLIENT_ID;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.ISSUER_ID;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.ISSUER_ID_URL;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.SUB_CLAIM;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.OpenIdConstants.USERINFO_ENCRYPTED_RESPONSE_ALG;

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
        this.sslConfig =  getSSLConfig(settings, configPath);
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

    private CloseableHttpClient createHttpClient(HttpCacheStorage httpCacheStorage) {
        HttpClientBuilder builder;

        if (httpCacheStorage != null) {
            builder = CachingHttpClients.custom().setCacheConfig(cacheConfig).setHttpCacheStorage(httpCacheStorage);
        } else {
            builder = HttpClients.custom();
        }

        builder.useSystemProperties();

        if (sslConfig != null) {
            final HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
                    .setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory())
                    .build();

            builder.setConnectionManager(cm);
        }

        return builder.build();
    }

    public  AuthCredentials extractCredentials0(SecurityRequest request, ThreadContext context) throws OpenSearchSecurityException {

        String encryptedResponseAlg = settings.get(USERINFO_ENCRYPTED_RESPONSE_ALG);

        try (CloseableHttpClient httpClient = createHttpClient(null)) {

            HttpGet httpGet = new HttpGet(this.userinfo_endpoint);

            RequestConfig requestConfig = RequestConfig.custom()
                    .setConnectionRequestTimeout(requestTimeoutMs, TimeUnit.MILLISECONDS)
                    .setConnectTimeout(requestTimeoutMs, TimeUnit.MILLISECONDS)
                    .build();

            httpGet.setConfig(requestConfig);
            httpGet.addHeader(AUTHORIZATION_HEADER, request.getHeaders().get(AUTHORIZATION_HEADER));

            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                if (response.getCode() < 200 || response.getCode() >= 300) {
                    throw new AuthenticatorUnavailableException("Error while getting " + this.userinfo_endpoint + ": " + response.getReasonPhrase());
                }

                HttpEntity httpEntity = response.getEntity();

                if (httpEntity == null) {
                    throw new AuthenticatorUnavailableException("Error while getting " + this.userinfo_endpoint + ": Empty response entity");
                }

                String contentType = httpEntity.getContentType();

                if (!contentType.equals(APPLICATION_JSON) && !contentType.equals(APPLICATION_JWT)) {
                    throw new AuthenticatorUnavailableException("Error while getting " + this.userinfo_endpoint + ": Invalid content type in response");
                }

                String userinfoContent = httpEntity.getContent().toString();

                if (contentType.equals(APPLICATION_JWT)) {
                    return openIdJwtAuthenticator.extractCredentials(request, context);
                } else {

                }

                // TODO: Make this return the formed creds from the response
                return null;
            }
        } catch (IOException e) {
            throw new AuthenticatorUnavailableException("Error while getting " + this.userinfo_endpoint + ": " + e, e);
        }
    }

    private String responseClaimsIncludeRequiredClaims(JWTClaimsSet claims, boolean isSigned) {

        String missing = "";

        if (claims.getClaim(SUB_CLAIM) == null || claims.getClaim(SUB_CLAIM).toString().isBlank()) {
            missing = missing.concat(SUB_CLAIM);
        }

        if (isSigned) {
            if (claims.getClaim("iss") == null || claims.getClaim("iss").toString().isBlank() || !claims.getClaim("iss").toString().equals(settings.get(ISSUER_ID_URL))) {
                missing = missing.concat("iss");
            }
            if (claims.getClaim("aud") == null || claims.getClaim("aud").toString().isBlank() || !claims.getClaim("aud").toString().equals(settings.get(CLIENT_ID))) {
                missing = missing.concat("aud");
            }
        }

        return missing;
    }

    private final class HTTPJwtKeyByOpenIdConnectAuthenticator extends AbstractHTTPJwtAuthenticator {

        public HTTPJwtKeyByOpenIdConnectAuthenticator(Settings settings, Path configPath) {
            super(settings,configPath);
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

        @Override
        public AuthCredentials extractCredentials(SecurityRequest request, ThreadContext context) throws OpenSearchSecurityException {
            String parsedToken = super.getJwtTokenString(request);
            SignedJWT jwt;
            boolean isJwtSigned = false;
            JWTClaimsSet claimsSet;

            try {
                jwt = super.jwtVerifier.getVerifiedJwtToken(parsedToken);
                if (jwt.getSignature() != null) {
                    isJwtSigned = true;
                }
                claimsSet = jwt.getJWTClaimsSet();
            } catch (OpenSearchSecurityException | ParseException | BadCredentialsException e) {
                throw new RuntimeException(e);
            }

            String missing = responseClaimsIncludeRequiredClaims(claimsSet, isJwtSigned);
            if (!missing.isBlank()) {
                throw new AuthenticatorUnavailableException("Missing expected claims: " + missing);
            }

            return super.extractCredentials(request, context);
        }

        @Override
        public String getType() {
            return "jwt-key-by-oidc";
        }
    }
}
