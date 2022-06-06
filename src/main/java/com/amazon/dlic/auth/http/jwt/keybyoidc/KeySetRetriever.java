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

import org.apache.cxf.rs.security.jose.jwk.JsonWebKeys;
import org.apache.cxf.rs.security.jose.jwk.JwkUtils;
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

import com.amazon.dlic.auth.http.jwt.oidc.json.OpenIdProviderConfiguration;
import com.amazon.dlic.util.SettingsBasedSSLConfigurator.SSLConfig;

import org.opensearch.security.DefaultObjectMapper;


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

	KeySetRetriever(String openIdConnectEndpoint, SSLConfig sslConfig, boolean useCacheForOidConnectEndpoint) {
		this.openIdConnectEndpoint = openIdConnectEndpoint;
		this.sslConfig = sslConfig;

		if (useCacheForOidConnectEndpoint) {
			cacheConfig = CacheConfig.custom().setMaxCacheEntries(10).setMaxObjectSize(1024L * 1024L).build();
			oidcHttpCacheStorage = new BasicHttpCacheStorage(cacheConfig);
		}
	}

	public JsonWebKeys get() throws AuthenticatorUnavailableException {
		String uri = getJwksUri();

		try (CloseableHttpClient httpClient = createHttpClient(null)) {

			HttpGet httpGet = new HttpGet(uri);

			RequestConfig requestConfig = RequestConfig.custom().setConnectionRequestTimeout(getRequestTimeoutMs())
					.setConnectTimeout(getRequestTimeoutMs()).setSocketTimeout(getRequestTimeoutMs()).build();

			httpGet.setConfig(requestConfig);

			try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
				StatusLine statusLine = response.getStatusLine();

				if (statusLine.getStatusCode() < 200 || statusLine.getStatusCode() >= 300) {
					throw new AuthenticatorUnavailableException("Error while getting " + uri + ": " + statusLine);
				}

				HttpEntity httpEntity = response.getEntity();

				if (httpEntity == null) {
					throw new AuthenticatorUnavailableException(
							"Error while getting " + uri + ": Empty response entity");
				}

				JsonWebKeys keySet = JwkUtils.readJwkSet(httpEntity.getContent());

				return keySet;
			}
		} catch (IOException e) {
			throw new AuthenticatorUnavailableException("Error while getting " + uri + ": " + e, e);
		}

	}

	String getJwksUri() throws AuthenticatorUnavailableException {

		try (CloseableHttpClient httpClient = createHttpClient(oidcHttpCacheStorage)) {

			HttpGet httpGet = new HttpGet(openIdConnectEndpoint);

			RequestConfig requestConfig = RequestConfig.custom().setConnectionRequestTimeout(getRequestTimeoutMs())
					.setConnectTimeout(getRequestTimeoutMs()).setSocketTimeout(getRequestTimeoutMs()).build();

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
					throw new AuthenticatorUnavailableException(
							"Error while getting " + openIdConnectEndpoint + ": " + statusLine);
				}

				HttpEntity httpEntity = response.getEntity();

				if (httpEntity == null) {
					throw new AuthenticatorUnavailableException(
							"Error while getting " + openIdConnectEndpoint + ": Empty response entity");
				}

				OpenIdProviderConfiguration parsedEntity = DefaultObjectMapper.objectMapper.readValue(httpEntity.getContent(),
						OpenIdProviderConfiguration.class);

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
			log.info("Cache status for KeySetRetriever:\noidcCacheHits: {}\noidcCacheHitsValidated: {}"
					+ "\noidcCacheModuleResponses: {}" + "\noidcCacheMisses: {}", oidcCacheHits, oidcCacheHitsValidated, oidcCacheModuleResponses, oidcCacheMisses);
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
