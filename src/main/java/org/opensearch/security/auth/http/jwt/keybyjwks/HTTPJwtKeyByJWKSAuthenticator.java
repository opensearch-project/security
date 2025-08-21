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

package org.opensearch.security.auth.http.jwt.keybyjwks;

import java.nio.file.Path;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.http.jwt.AbstractHTTPJwtAuthenticator;
import org.opensearch.security.auth.http.jwt.keybyoidc.KeyProvider;
import org.opensearch.security.auth.http.jwt.keybyoidc.KeySetRetriever;
import org.opensearch.security.auth.http.jwt.keybyoidc.SelfRefreshingKeySet;
import org.opensearch.security.util.SettingsBasedSSLConfigurator;

/**
 * JWT authenticator that uses JWKS (JSON Web Key Set) endpoints for key retrieval.
 *
 * This authenticator extends AbstractHTTPJwtAuthenticator and provides JWKS-specific
 * key provider initialization. It supports direct JWKS endpoint access with caching,
 * SSL configuration, and automatic key refresh.
 *
 * Configuration:
 * - jwks_uri: Direct JWKS endpoint URL (required)
 * - cache_jwks_endpoint: Enable/disable caching (default: true)
 * - jwks_request_timeout_ms: Request timeout in milliseconds (default: 5000)
 * - jwks_queued_thread_timeout_ms: Queued thread timeout (default: 2500)
 * - refresh_rate_limit_time_window_ms: Rate limit window (default: 10000)
 * - refresh_rate_limit_count: Max refreshes per window (default: 10)
 */
public class HTTPJwtKeyByJWKSAuthenticator extends AbstractHTTPJwtAuthenticator {

    private final static Logger log = LogManager.getLogger(HTTPJwtKeyByJWKSAuthenticator.class);

    public HTTPJwtKeyByJWKSAuthenticator(Settings settings, Path configPath) {
        super(settings, configPath);
    }

    @Override
    protected KeyProvider initKeyProvider(Settings settings, Path configPath) throws Exception {
        String jwksUri = settings.get("jwks_uri");
        log.warn("Initializing JWKS key provider with endpoint: {}", jwksUri);

        if (jwksUri == null || jwksUri.isBlank()) {
            throw new IllegalArgumentException("jwks_uri is required for JWKS authenticator");
        }

        log.info("Initializing JWKS key provider with endpoint: {}", jwksUri);

        // Initialize configuration parameters
        int jwksRequestTimeoutMs = settings.getAsInt("jwks_request_timeout_ms", 5000);
        int jwksQueuedThreadTimeoutMs = settings.getAsInt("jwks_queued_thread_timeout_ms", 2500);
        int refreshRateLimitTimeWindowMs = settings.getAsInt("refresh_rate_limit_time_window_ms", 10000);
        int refreshRateLimitCount = settings.getAsInt("refresh_rate_limit_count", 10);
        boolean cacheJwksEndpoint = settings.getAsBoolean("cache_jwks_endpoint", true);

        // Create key set retriever for direct JWKS endpoint access
        KeySetRetriever keySetRetriever = new KeySetRetriever(
            getSSLConfig(settings, configPath),
            cacheJwksEndpoint,
            jwksUri
        );
        keySetRetriever.setRequestTimeoutMs(jwksRequestTimeoutMs);

        // Create self-refreshing key set with caching and rate limiting
        SelfRefreshingKeySet selfRefreshingKeySet = new SelfRefreshingKeySet(keySetRetriever);
        selfRefreshingKeySet.setRequestTimeoutMs(jwksRequestTimeoutMs);
        selfRefreshingKeySet.setQueuedThreadTimeoutMs(jwksQueuedThreadTimeoutMs);
        selfRefreshingKeySet.setRefreshRateLimitTimeWindowMs(refreshRateLimitTimeWindowMs);
        selfRefreshingKeySet.setRefreshRateLimitCount(refreshRateLimitCount);

        log.info("JWKS key provider successfully initialized");
        return selfRefreshingKeySet;
    }

    private static SettingsBasedSSLConfigurator.SSLConfig getSSLConfig(Settings settings, Path configPath) throws Exception {
        return new SettingsBasedSSLConfigurator(settings, configPath, "jwks").buildSSLConfig();
    }

    @Override
    public String getType() {
        return "jwt-key-by-jwks";
    }
}
