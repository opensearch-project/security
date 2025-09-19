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

package org.opensearch.security.auth.http.jwt.keybyoidc;

import java.io.IOException;
import java.text.ParseException;
import java.util.concurrent.TimeUnit;

import org.apache.hc.client5.http.cache.HttpCacheContext;
import org.apache.hc.client5.http.cache.HttpCacheStorage;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.cache.BasicHttpCacheStorage;
import org.apache.hc.client5.http.impl.cache.CacheConfig;
import org.apache.hc.client5.http.impl.cache.CachingHttpClients;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auth.http.jwt.oidc.json.OpenIdProviderConfiguration;
import org.opensearch.security.util.SettingsBasedSSLConfigurator.SSLConfig;

import com.nimbusds.jose.jwk.JWKSet;
import joptsimple.internal.Strings;

public class KeySetRetriever implements KeySetProvider {
    private final static Logger log = LogManager.getLogger(KeySetRetriever.class);
    private static final long CACHE_STATUS_LOG_INTERVAL_MS = 60L * 60L * 1000L;

    private String openIdConnectEndpoint;
    private SSLConfig sslConfig;
    private int requestTimeoutMs = 10000;
    private CacheConfig cacheConfig;
    private HttpCacheStorage oidcHttpCacheStorage;
    private int oidcCacheHits = 0;
    private int oidcCacheMisses = 0;
    private int oidcCacheHitsValidated = 0;
    private int oidcCacheModuleResponses = 0;
    private long oidcRequests = 0;
    private long lastCacheStatusLog = 0;
    private String jwksUri;

    // Security validation settings (optional, for JWKS endpoints)
    private long maxResponseSizeBytes = -1; // -1 means no limit
    private int maxKeyCount = -1; // -1 means no limit
    private boolean enableSecurityValidation = false;

    KeySetRetriever(String openIdConnectEndpoint, SSLConfig sslConfig, boolean useCacheForOidConnectEndpoint) {
        this.openIdConnectEndpoint = openIdConnectEndpoint;
        this.sslConfig = sslConfig;

        configureCache(useCacheForOidConnectEndpoint);
    }

    KeySetRetriever(SSLConfig sslConfig, boolean useCacheForOidConnectEndpoint, String jwksUri) {
        this.jwksUri = jwksUri;
        this.sslConfig = sslConfig;

        configureCache(useCacheForOidConnectEndpoint);
    }

    /**
     * Factory method to create a KeySetRetriever for JWKS endpoint access.
     * This method provides a public API for creating KeySetRetriever instances
     * with built-in security validation to protect against malicious JWKS endpoints.
     *
     * @param sslConfig SSL configuration for HTTPS connections
     * @param useCacheForJwksEndpoint whether to enable caching for JWKS endpoint
     *                                When true, JWKS responses will be cached to improve performance
     *                                and reduce network calls to the JWKS endpoint.
     * @param jwksUri the JWKS endpoint URI
     * @param maxResponseSizeBytes maximum allowed HTTP response size in bytes
     * @param maxKeyCount maximum number of keys allowed in JWKS
     * @return a new KeySetRetriever instance with security validation enabled
     */
    public static KeySetRetriever createForJwksUri(
        SSLConfig sslConfig,
        boolean useCacheForJwksEndpoint,
        String jwksUri,
        long maxResponseSizeBytes,
        int maxKeyCount
    ) {
        KeySetRetriever retriever = new KeySetRetriever(sslConfig, useCacheForJwksEndpoint, jwksUri);
        retriever.enableSecurityValidation = true;
        retriever.maxResponseSizeBytes = maxResponseSizeBytes;
        retriever.maxKeyCount = maxKeyCount;
        return retriever;
    }

    public JWKSet get() throws AuthenticatorUnavailableException {
        String uri = getJwksUri();

        // Use cache storage if it's configured
        HttpCacheStorage cacheStorage = oidcHttpCacheStorage;

        try (CloseableHttpClient httpClient = createHttpClient(cacheStorage)) {

            HttpGet httpGet = new HttpGet(uri);

            RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(getRequestTimeoutMs(), TimeUnit.MILLISECONDS)
                .setConnectTimeout(getRequestTimeoutMs(), TimeUnit.MILLISECONDS)
                .build();

            httpGet.setConfig(requestConfig);

            HttpCacheContext httpContext = null;
            if (cacheStorage != null) {
                httpContext = new HttpCacheContext();
            }

            try (CloseableHttpResponse response = httpClient.execute(httpGet, httpContext)) {
                if (httpContext != null) {
                    logCacheResponseStatus(httpContext, true);
                }
                if (response.getCode() < 200 || response.getCode() >= 300) {
                    throw new AuthenticatorUnavailableException("Error while getting " + uri + ": " + response.getReasonPhrase());
                }

                HttpEntity httpEntity = response.getEntity();

                if (httpEntity == null) {
                    throw new AuthenticatorUnavailableException("Error while getting " + uri + ": Empty response entity");
                }

                // Apply security validation if enabled (for JWKS endpoints)
                if (enableSecurityValidation) {
                    // Validate response size
                    if (maxResponseSizeBytes > 0) {
                        long contentLength = httpEntity.getContentLength();
                        if (contentLength > maxResponseSizeBytes) {
                            throw new AuthenticatorUnavailableException(
                                String.format(
                                    "JWKS response too large from %s: %d bytes (max: %d)",
                                    uri,
                                    contentLength,
                                    maxResponseSizeBytes
                                )
                            );
                        }
                    }
                }

                // Standard loading for both OIDC and JWKS endpoints
                JWKSet keySet = JWKSet.load(httpEntity.getContent());

                // Post-load validation for JWKS if enabled - HARD LIMIT
                if (enableSecurityValidation && maxKeyCount > 0 && keySet.getKeys().size() > maxKeyCount) {
                    throw new AuthenticatorUnavailableException(
                        String.format("JWKS from %s contains %d keys, but max allowed is %d", uri, keySet.getKeys().size(), maxKeyCount)
                    );
                }

                return keySet;
            } catch (ParseException e) {
                throw new AuthenticatorUnavailableException("Error parsing JWKS from " + uri + ": " + e.getMessage(), e);
            }
        } catch (IOException e) {
            throw new AuthenticatorUnavailableException("Error while getting " + uri + ": " + e, e);
        }

    }

    String getJwksUri() throws AuthenticatorUnavailableException {

        if (!Strings.isNullOrEmpty(jwksUri)) {
            return jwksUri;
        }

        if (Strings.isNullOrEmpty(openIdConnectEndpoint)) {
            throw new AuthenticatorUnavailableException(
                "Either openid_connect_url or jwks_uri must be configured for OIDC Authentication backend"
            );
        }

        try (CloseableHttpClient httpClient = createHttpClient(oidcHttpCacheStorage)) {

            HttpGet httpGet = new HttpGet(openIdConnectEndpoint);

            RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(getRequestTimeoutMs(), TimeUnit.MILLISECONDS)
                .setConnectTimeout(getRequestTimeoutMs(), TimeUnit.MILLISECONDS)
                .build();

            httpGet.setConfig(requestConfig);

            HttpCacheContext httpContext = null;

            if (oidcHttpCacheStorage != null) {
                httpContext = new HttpCacheContext();
            }

            try (CloseableHttpResponse response = httpClient.execute(httpGet, httpContext)) {
                if (httpContext != null) {
                    logCacheResponseStatus(httpContext);
                }

                if (response.getCode() < 200 || response.getCode() >= 300) {
                    throw new AuthenticatorUnavailableException(
                        "Error while getting " + openIdConnectEndpoint + ": " + response.getReasonPhrase()
                    );
                }

                HttpEntity httpEntity = response.getEntity();

                if (httpEntity == null) {
                    throw new AuthenticatorUnavailableException("Error while getting " + openIdConnectEndpoint + ": Empty response entity");
                }

                OpenIdProviderConfiguration parsedEntity = DefaultObjectMapper.objectMapper.readValue(
                    httpEntity.getContent(),
                    OpenIdProviderConfiguration.class
                );

                return parsedEntity.getJwksUri();

            }

        } catch (IOException e) {
            throw new AuthenticatorUnavailableException("Error while getting " + openIdConnectEndpoint + ": " + e, e);
        }

    }

    public int getRequestTimeoutMs() {
        return requestTimeoutMs;
    }

    public void setRequestTimeoutMs(int httpTimeoutMs) {
        this.requestTimeoutMs = httpTimeoutMs;
    }

    private void logCacheResponseStatus(HttpCacheContext httpContext) {
        logCacheResponseStatus(httpContext, false);
    }

    private void logCacheResponseStatus(HttpCacheContext httpContext, boolean isJwksRequest) {
        this.oidcRequests++;

        // Handle cache statistics based on the response status
        // For OIDC discovery flow, only count the JWKS request (not the discovery request)
        // For direct JWKS URI, count all requests
        boolean shouldCountStats = (jwksUri != null) || isJwksRequest;

        if (!shouldCountStats) {
            log.debug("Skipping cache statistics for OIDC discovery request #{}", this.oidcRequests);
            return;
        }

        if (httpContext.getCacheResponseStatus() == null) {
            if (oidcHttpCacheStorage != null) {
                this.oidcCacheMisses++;
                log.debug("Null cache status - counting as cache miss. Total misses: {}", this.oidcCacheMisses);
            }
        } else {
            switch (httpContext.getCacheResponseStatus()) {
                case CACHE_HIT:
                    this.oidcCacheHits++;
                    break;
                case CACHE_MODULE_RESPONSE:
                    this.oidcCacheModuleResponses++;
                    break;
                case CACHE_MISS:
                    this.oidcCacheMisses++;
                    break;
                case VALIDATED:
                    this.oidcCacheHits++;
                    this.oidcCacheHitsValidated++;
                    break;
            }
        }

        long now = System.currentTimeMillis();

        if (this.oidcRequests >= 2 && now - lastCacheStatusLog > CACHE_STATUS_LOG_INTERVAL_MS) {
            log.info(
                "Cache status for KeySetRetriever:\noidcCacheHits: {}\noidcCacheHitsValidated: {}"
                    + "\noidcCacheModuleResponses: {}"
                    + "\noidcCacheMisses: {}",
                oidcCacheHits,
                oidcCacheHitsValidated,
                oidcCacheModuleResponses,
                oidcCacheMisses
            );
            lastCacheStatusLog = now;
        }
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
                .setTlsSocketStrategy(new DefaultClientTlsStrategy(sslConfig.getSslContext()))
                .build();

            builder.setConnectionManager(cm);
        }

        return builder.build();
    }

    private void configureCache(boolean useCacheForOidConnectEndpoint) {
        if (useCacheForOidConnectEndpoint) {
            cacheConfig = CacheConfig.custom().setMaxCacheEntries(10).setMaxObjectSize(1024L * 1024L).build();
            oidcHttpCacheStorage = new BasicHttpCacheStorage(cacheConfig);
        }
    }

    public int getOidcCacheHits() {
        return oidcCacheHits;
    }

    public int getOidcCacheMisses() {
        return oidcCacheMisses;
    }

    public int getOidcCacheHitsValidated() {
        return oidcCacheHitsValidated;
    }

    public int getOidcCacheModuleResponses() {
        return oidcCacheModuleResponses;
    }
}
