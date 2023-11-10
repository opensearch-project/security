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

import java.nio.file.Path;

import org.opensearch.common.settings.Settings;

import com.amazon.dlic.auth.http.jwt.AbstractHTTPJwtAuthenticator;
import com.amazon.dlic.util.SettingsBasedSSLConfigurator;

public class HTTPJwtKeyByOpenIdConnectAuthenticator extends AbstractHTTPJwtAuthenticator {

    // private final static Logger log = LogManager.getLogger(HTTPJwtKeyByOpenIdConnectAuthenticator.class);

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

    private static SettingsBasedSSLConfigurator.SSLConfig getSSLConfig(Settings settings, Path configPath) throws Exception {
        return new SettingsBasedSSLConfigurator(settings, configPath, "openid_connect_idp").buildSSLConfig();
    }

    @Override
    public String getType() {
        return "jwt-key-by-oidc";
    }

}
