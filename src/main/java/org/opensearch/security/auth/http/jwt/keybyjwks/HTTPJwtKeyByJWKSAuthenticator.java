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

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.Strings;
import org.opensearch.security.auth.http.jwt.AbstractHTTPJwtAuthenticator;
import org.opensearch.security.auth.http.jwt.HTTPJwtAuthenticator;
import org.opensearch.security.auth.http.jwt.keybyoidc.KeyProvider;
import org.opensearch.security.auth.http.jwt.keybyoidc.KeySetRetriever;
import org.opensearch.security.auth.http.jwt.keybyoidc.SelfRefreshingKeySet;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.SettingsBasedSSLConfigurator;

/**
 * JWT authenticator that uses JWKS (JSON Web Key Set) endpoints for key retrieval.
 *
 * This authenticator extends AbstractHTTPJwtAuthenticator and provides JWKS-specific
 * key provider initialization. It supports direct JWKS endpoint access with caching,
 * SSL configuration, automatic key refresh, and enhanced security features to protect
 * against malicious JWKS endpoints.
 *
 * Security Features:
 * - Response size validation before parsing to prevent memory exhaustion
 * - Hard key count limit after parsing to reject oversized JWKS
 * - Configurable timeouts and rate limiting
 *
 * Configuration:
 * - jwks_uri: Direct JWKS endpoint URL (required)
 * - cache_jwks_endpoint: Enable/disable caching (default: true)
 * - jwks_request_timeout_ms: Request timeout in milliseconds (default: 5000)
 * - jwks_queued_thread_timeout_ms: Queued thread timeout (default: 2500)
 * - refresh_rate_limit_time_window_ms: Rate limit window (default: 10000)
 * - refresh_rate_limit_count: Max refreshes per window (default: 10)
 * - max_jwks_keys: HARD LIMIT - Rejects JWKS if exceeded (default: 10)
 * - max_jwks_response_size_bytes: Max HTTP response size (default: 1MB)
 */
public class HTTPJwtKeyByJWKSAuthenticator extends AbstractHTTPJwtAuthenticator {

    private final static Logger log = LogManager.getLogger(HTTPJwtKeyByJWKSAuthenticator.class);

    // Fallback to static JWT authenticator if jwks_uri is null
    private final HTTPJwtAuthenticator staticJwtAuthenticator;
    private final boolean useJwks;

    public HTTPJwtKeyByJWKSAuthenticator(Settings settings, Path configPath) {
        super(settings, configPath);

        String jwksUri = settings.get("jwks_uri");
        this.useJwks = !Strings.isNullOrEmpty(jwksUri);

        // Initialize static JWT authenticator as fallback if jwks_uri is not configured
        if (!useJwks) {
            log.info("jwks_uri is not configured, falling back to static JWT authentication");
            this.staticJwtAuthenticator = new HTTPJwtAuthenticator(settings, configPath);
        } else {
            this.staticJwtAuthenticator = null;
        }
    }

    @Override
    protected KeyProvider initKeyProvider(Settings settings, Path configPath) throws Exception {
        String jwksUri = settings.get("jwks_uri");

        // If jwks_uri is not configured, return null (will use static JWT fallback)
        if (jwksUri == null || jwksUri.isBlank()) {
            log.info("jwks_uri is not configured, will use static JWT authentication fallback");
            return null;
        }

        log.info("Initializing JWKS key provider with endpoint: {}", jwksUri);

        // Initialize configuration parameters
        int jwksRequestTimeoutMs = settings.getAsInt("jwks_request_timeout_ms", 5000);
        int jwksQueuedThreadTimeoutMs = settings.getAsInt("jwks_queued_thread_timeout_ms", 2500);
        int refreshRateLimitTimeWindowMs = settings.getAsInt("refresh_rate_limit_time_window_ms", 10000);
        int refreshRateLimitCount = settings.getAsInt("refresh_rate_limit_count", 10);
        boolean cacheJwksEndpoint = settings.getAsBoolean("cache_jwks_endpoint", true);
        int maxJwksKeys = settings.getAsInt("max_jwks_keys", 10); // Default to 10 keys

        log.info("Initializing JWKS key provider with endpoint: {} (max keys: {})", jwksUri, maxJwksKeys);

        // Add security configuration parameters
        long maxJwksResponseSizeBytes = settings.getAsLong("max_jwks_response_size_bytes", 1024L * 1024L); // 1MB default

        // Create secure key set retriever with HARD LIMIT enforcement using maxJwksKeys
        KeySetRetriever keySetRetriever = KeySetRetriever.createForJwksUri(
            getSSLConfig(settings, configPath),
            cacheJwksEndpoint,
            jwksUri,
            maxJwksResponseSizeBytes,
            maxJwksKeys  // HARD LIMIT - throws exception if exceeded
        );
        keySetRetriever.setRequestTimeoutMs(jwksRequestTimeoutMs);

        // Create self-refreshing key set with caching and rate limiting
        SelfRefreshingKeySet selfRefreshingKeySet = new SelfRefreshingKeySet(keySetRetriever);
        selfRefreshingKeySet.setRequestTimeoutMs(jwksRequestTimeoutMs);
        selfRefreshingKeySet.setQueuedThreadTimeoutMs(jwksQueuedThreadTimeoutMs);
        selfRefreshingKeySet.setRefreshRateLimitTimeWindowMs(refreshRateLimitTimeWindowMs);
        selfRefreshingKeySet.setRefreshRateLimitCount(refreshRateLimitCount);

        log.info("JWKS key provider successfully initialized with key limit: {}", maxJwksKeys);
        return selfRefreshingKeySet;
    }

    @Override
    public AuthCredentials extractCredentials(final SecurityRequest request, final ThreadContext context)
        throws OpenSearchSecurityException {

        // If jwks_uri is not configured, delegate to static JWT authenticator
        if (!useJwks && staticJwtAuthenticator != null) {
            log.debug("Delegating to static JWT authenticator since jwks_uri is not configured");
            return staticJwtAuthenticator.extractCredentials(request, context);
        }

        // Otherwise, use the standard JWKS authentication flow
        return super.extractCredentials(request, context);
    }

    private static SettingsBasedSSLConfigurator.SSLConfig getSSLConfig(Settings settings, Path configPath) throws Exception {
        return new SettingsBasedSSLConfigurator(settings, configPath, "jwks").buildSSLConfig();
    }

    @Override
    public String getType() {
        return "jwt";
    }
}
