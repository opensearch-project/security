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

package org.opensearch.security.http;

import java.util.Optional;

import org.apache.hc.core5.http.HttpHeaders;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.action.apitokens.ApiTokenRepository;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.user.AuthCredentials;

import static org.opensearch.security.action.apitokens.ApiTokenRepository.TOKEN_PREFIX;

public class ApiTokenAuthenticator implements HTTPAuthenticator {

    private static final String API_KEY_PREFIX = "apikey ";

    public static final String API_TOKEN_USER_PREFIX = "token:";

    public Logger log = LogManager.getLogger(this.getClass());

    private final boolean apiTokenEnabled;
    private final ApiTokenRepository apiTokenRepository;

    public ApiTokenAuthenticator(Settings settings, String clusterName, ApiTokenRepository apiTokenRepository) {
        this.apiTokenEnabled = Boolean.parseBoolean(settings.get("enabled", "true"));
        this.apiTokenRepository = apiTokenRepository;
    }

    @Override
    public AuthCredentials extractCredentials(final SecurityRequest request, final ThreadContext context) {
        if (!apiTokenEnabled) {
            log.debug("Api token authentication is disabled");
            return null;
        }

        String token = extractTokenFromHeader(request);
        if (token == null) {
            return null;
        }

        if (!token.startsWith(TOKEN_PREFIX)) {
            log.debug("Token does not have expected prefix");
            return null;
        }

        String hash = ApiTokenRepository.hashToken(token);
        if (!apiTokenRepository.isValidToken(hash)) {
            log.debug("Api token is not valid");
            return null;
        }

        ApiTokenRepository.TokenEntry metadata = apiTokenRepository.getTokenMetadata(hash);
        if (metadata == null) {
            log.warn("Api token metadata not found");
            return null;
        }

        if (metadata.isExpired()) {
            log.debug("Api token is expired");
            return null;
        }

        return new AuthCredentials(API_TOKEN_USER_PREFIX + apiTokenRepository.getTokenName(hash), java.util.List.of(), "").markComplete();
    }

    private String extractTokenFromHeader(SecurityRequest request) {
        String header = request.header(HttpHeaders.AUTHORIZATION);
        if (header == null || header.isEmpty()) {
            log.debug("No token found in '{}' header", HttpHeaders.AUTHORIZATION);
            return null;
        }
        String normalizedHeader = header.trim().toLowerCase(java.util.Locale.ROOT);
        if (!normalizedHeader.startsWith(API_KEY_PREFIX)) {
            log.debug("No ApiKey scheme found in header");
            return null;
        }
        return header.substring(header.toLowerCase(java.util.Locale.ROOT).indexOf(API_KEY_PREFIX) + API_KEY_PREFIX.length()).trim();
    }

    @Override
    public Optional<SecurityResponse> reRequestAuthentication(final SecurityRequest response, AuthCredentials creds) {
        return Optional.empty();
    }

    @Override
    public String getType() {
        return "apitoken";
    }

    @Override
    public boolean supportsImpersonation() {
        return false;
    }
}
