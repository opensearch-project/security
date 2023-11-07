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
import java.text.ParseException;

import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.cache.HttpCacheContext;
import org.apache.http.client.cache.HttpCacheStorage;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.cache.BasicHttpCacheStorage;
import org.apache.http.impl.client.cache.CacheConfig;
import org.apache.http.impl.client.cache.CachingHttpClients;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.DefaultObjectMapper;

import com.amazon.dlic.auth.http.jwt.oidc.json.OpenIdProviderConfiguration;
import com.amazon.dlic.util.SettingsBasedSSLConfigurator.SSLConfig;
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
                .setConnectionRequestTimeout(getRequestTimeoutMs())
                .setConnectTimeout(getRequestTimeoutMs())
                .setSocketTimeout(getRequestTimeoutMs())
                .build();

            httpGet.setConfig(requestConfig);

            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                StatusLine statusLine = response.getStatusLine();

                if (statusLine.getStatusCode() < 200 || statusLine.getStatusCode() >= 300) {
                    throw new AuthenticatorUnavailableException("Error while getting " + uri + ": " + statusLine);
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
                .setConnectionRequestTimeout(getRequestTimeoutMs())
                .setConnectTimeout(getRequestTimeoutMs())
                .setSocketTimeout(getRequestTimeoutMs())
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

                StatusLine statusLine = response.getStatusLine();

                if (statusLine.getStatusCode() < 200 || statusLine.getStatusCode() >= 300) {
                    throw new AuthenticatorUnavailableException("Error while getting " + openIdConnectEndpoint + ": " + statusLine);
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
            builder.setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory());
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
