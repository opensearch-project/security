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

    public JWKSet get() throws AuthenticatorUnavailableException {
        String uri = getJwksUri();

        try (CloseableHttpClient httpClient = createHttpClient(null)) {

            HttpGet httpGet = new HttpGet(uri);

            RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(getRequestTimeoutMs(), TimeUnit.MILLISECONDS)
                .setConnectTimeout(getRequestTimeoutMs(), TimeUnit.MILLISECONDS)
                .build();

            httpGet.setConfig(requestConfig);

            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                log.warn("JWKS retrieved from " + uri + " successfully");
                log.warn("response code: " + response.getCode() + " - " + response.getReasonPhrase() + " - " + response.getStatusLine());
                if (response.getCode() < 200 || response.getCode() >= 300) {
                    throw new AuthenticatorUnavailableException("Error while getting " + uri + ": " + response.getReasonPhrase());
                }

                HttpEntity httpEntity = response.getEntity();

                if (httpEntity == null) {
                    throw new AuthenticatorUnavailableException("Error while getting " + uri + ": Empty response entity");
                }
                JWKSet keySet = JWKSet.load(httpEntity.getContent());

                return keySet;
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        } catch (IOException e) {
            throw new AuthenticatorUnavailableException("Error while getting " + uri + ": " + e, e);
        }

    }

    String getJwksUri() throws AuthenticatorUnavailableException {

        if (!Strings.isNullOrEmpty(jwksUri)) {
            log.warn("Using jwks_uri: " + jwksUri);
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
        this.oidcRequests++;

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
                this.oidcCacheHitsValidated++;
                break;
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
