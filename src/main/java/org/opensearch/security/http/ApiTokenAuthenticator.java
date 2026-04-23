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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.hc.core5.http.HttpHeaders;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.action.apitokens.ApiTokenRepository;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.user.AuthCredentials;

import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.action.apitokens.ApiTokenRepository.TOKEN_PREFIX;
import static org.opensearch.security.util.AuthTokenUtils.isAccessToRestrictedEndpoints;

public class ApiTokenAuthenticator implements HTTPAuthenticator {

    private static final String REGEX_PATH_PREFIX = "/(" + LEGACY_OPENDISTRO_PREFIX + "|" + PLUGINS_PREFIX + ")/" + "(.*)";
    private static final Pattern PATTERN_PATH_PREFIX = Pattern.compile(REGEX_PATH_PREFIX);
    private static final Pattern API_KEY_HEADER = Pattern.compile("^\\s*ApiKey\\s.*", Pattern.CASE_INSENSITIVE);
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
            log.error("Api token authentication is disabled");
            return null;
        }

        String token = extractTokenFromHeader(request);
        if (token == null) {
            return null;
        }

        if (!isRequestAllowed(request)) {
            return null;
        }

        if (!token.startsWith(TOKEN_PREFIX)) {
            log.debug("Token does not have expected prefix");
            return null;
        }

        String hash = ApiTokenRepository.hashToken(token);
        if (!apiTokenRepository.isValidToken(hash)) {
            log.error("Api token is not valid");
            return null;
        }

        ApiTokenRepository.TokenMetadata metadata = apiTokenRepository.getTokenMetadata(hash);
        if (metadata == null) {
            log.error("Api token metadata not found");
            return null;
        }

        if (metadata.isExpired()) {
            log.debug("Api token is expired");
            return null;
        }

        return new AuthCredentials(API_TOKEN_USER_PREFIX + hash, java.util.List.of(), "").markComplete();
    }

    private String extractTokenFromHeader(SecurityRequest request) {
        String header = request.header(HttpHeaders.AUTHORIZATION);
        if (header == null || header.isEmpty()) {
            log.debug("No token found in '{}' header", HttpHeaders.AUTHORIZATION);
            return null;
        }
        if (!API_KEY_HEADER.matcher(header).matches()) {
            log.debug("No ApiKey scheme found in header");
            return null;
        }
        return header.substring(header.toLowerCase().indexOf(API_KEY_PREFIX) + API_KEY_PREFIX.length());
    }

    public Boolean isRequestAllowed(final SecurityRequest request) {
        Matcher matcher = PATTERN_PATH_PREFIX.matcher(request.path());
        final String suffix = matcher.matches() ? matcher.group(2) : null;
        if (isAccessToRestrictedEndpoints(request, suffix)) {
            final OpenSearchException exception = ExceptionUtils.invalidUsageOfApiTokenException();
            log.error(exception.toString());
            return false;
        }
        return true;
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
