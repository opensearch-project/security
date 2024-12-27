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

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.hc.core5.http.HttpHeaders;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.action.apitokens.ApiToken;
import org.opensearch.security.action.apitokens.ApiTokenIndexListenerCache;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.authtoken.jwt.EncryptionDecryptionUtil;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.KeyUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.security.WeakKeyException;

import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.filter.SecurityRestFilter.API_TOKEN_CLUSTERPERM_KEY;
import static org.opensearch.security.filter.SecurityRestFilter.API_TOKEN_INDEXPERM_KEY;
import static org.opensearch.security.util.AuthTokenUtils.isAccessToRestrictedEndpoints;

public class ApiTokenAuthenticator implements HTTPAuthenticator {

    private static final int MINIMUM_SIGNING_KEY_BIT_LENGTH = 512;
    private static final String REGEX_PATH_PREFIX = "/(" + LEGACY_OPENDISTRO_PREFIX + "|" + PLUGINS_PREFIX + ")/" + "(.*)";
    private static final Pattern PATTERN_PATH_PREFIX = Pattern.compile(REGEX_PATH_PREFIX);

    public Logger log = LogManager.getLogger(this.getClass());

    private static final Pattern BEARER = Pattern.compile("^\\s*Bearer\\s.*", Pattern.CASE_INSENSITIVE);
    private static final String BEARER_PREFIX = "bearer ";

    private final JwtParser jwtParser;
    private final String encryptionKey;
    private final Boolean apiTokenEnabled;
    private final String clusterName;

    private final EncryptionDecryptionUtil encryptionUtil;

    @SuppressWarnings("removal")
    public ApiTokenAuthenticator(Settings settings, String clusterName) {
        String apiTokenEnabledSetting = settings.get("enabled", "true");
        apiTokenEnabled = Boolean.parseBoolean(apiTokenEnabledSetting);
        encryptionKey = settings.get("encryption_key");

        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        jwtParser = AccessController.doPrivileged(new PrivilegedAction<JwtParser>() {
            @Override
            public JwtParser run() {
                JwtParserBuilder builder = initParserBuilder(settings.get("signing_key"));
                return builder.build();
            }
        });
        this.clusterName = clusterName;
        this.encryptionUtil = new EncryptionDecryptionUtil(encryptionKey);
    }

    private JwtParserBuilder initParserBuilder(final String signingKey) {
        if (signingKey == null) {
            throw new OpenSearchSecurityException("Unable to find api token authenticator signing_key");
        }

        final int signingKeyLengthBits = signingKey.length() * 8;
        if (signingKeyLengthBits < MINIMUM_SIGNING_KEY_BIT_LENGTH) {
            throw new OpenSearchSecurityException(
                "Signing key size was "
                    + signingKeyLengthBits
                    + " bits, which is not secure enough. Please use a signing_key with a size >= "
                    + MINIMUM_SIGNING_KEY_BIT_LENGTH
                    + " bits."
            );
        }
        JwtParserBuilder jwtParserBuilder = KeyUtils.createJwtParserBuilderFromSigningKey(signingKey, log);

        return jwtParserBuilder;
    }

    private String extractClusterPermissionsFromClaims(Claims claims) {
        Object cp = claims.get("cp");
        String clusterPermissions = "";

        if (cp != null) {
            clusterPermissions = encryptionUtil.decrypt(cp.toString());
        } else {
            log.warn("This is a malformed Api Token");
        }

        return clusterPermissions;
    }

    private List<ApiToken.IndexPermission> extractIndexPermissionFromClaims(Claims claims) throws IOException {
        Object ip = claims.get("ip");

        if (ip != null) {
            String decryptedPermissions = encryptionUtil.decrypt(ip.toString());

            try (
                XContentParser parser = XContentType.JSON.xContent()
                    .createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION, decryptedPermissions)
            ) {

                // Use built-in array parsing
                List<ApiToken.IndexPermission> permissions = new ArrayList<>();

                // Move to start of array
                parser.nextToken();  // START_ARRAY
                while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                    permissions.add(ApiToken.IndexPermission.fromXContent(parser));
                }
                return permissions;
            } catch (Exception e) {
                log.error("Error extracting index permissions", e);
                return List.of();
            }

        }

        return List.of();
    }

    @Override
    @SuppressWarnings("removal")
    public AuthCredentials extractCredentials(final SecurityRequest request, final ThreadContext context)
        throws OpenSearchSecurityException {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        AuthCredentials creds = AccessController.doPrivileged(new PrivilegedAction<AuthCredentials>() {
            @Override
            public AuthCredentials run() {
                return extractCredentials0(request, context);
            }
        });

        return creds;
    }

    private AuthCredentials extractCredentials0(final SecurityRequest request, final ThreadContext context) {
        if (!apiTokenEnabled) {
            log.error("Api token authentication is disabled");
            return null;
        }
        ApiTokenIndexListenerCache cache = ApiTokenIndexListenerCache.getInstance();

        String jwtToken = extractJwtFromHeader(request);
        if (jwtToken == null) {
            return null;
        }

        if (!isRequestAllowed(request)) {
            return null;
        }

        // TODO: handle revocation different from deletion?
        if (!cache.getJtis().contains(encryptionUtil.encrypt(jwtToken))) {
            log.debug("Token is not allowlisted");
            return null;
        }

        try {
            final Claims claims = jwtParser.parseClaimsJws(jwtToken).getBody();

            final String subject = claims.getSubject();
            if (subject == null) {
                log.error("Valid jwt api token with no subject");
                return null;
            }

            final String issuer = claims.getIssuer();
            if (!clusterName.equals(issuer)) {
                log.error("The issuer of this api token does not match the current cluster identifier");
                return null;
            }

            String clusterPermissions = extractClusterPermissionsFromClaims(claims);
            List<ApiToken.IndexPermission> indexPermissions = extractIndexPermissionFromClaims(claims);

            final AuthCredentials ac = new AuthCredentials(subject, List.of(), "").markComplete();

            context.putTransient(API_TOKEN_CLUSTERPERM_KEY, clusterPermissions);
            context.putTransient(API_TOKEN_INDEXPERM_KEY, indexPermissions);

            return ac;

        } catch (WeakKeyException e) {
            log.error("Cannot authenticate user with JWT because of ", e);
            return null;
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid or expired JWT token.", e);
            }
        }

        // Return null for the authentication failure
        return null;
    }

    private String extractJwtFromHeader(SecurityRequest request) {
        String jwtToken = request.header(HttpHeaders.AUTHORIZATION);

        if (jwtToken == null || jwtToken.isEmpty()) {
            logDebug("No JWT token found in '{}' header", HttpHeaders.AUTHORIZATION);
            return null;
        }

        if (!BEARER.matcher(jwtToken).matches() || !jwtToken.toLowerCase().contains(BEARER_PREFIX)) {
            logDebug("No Bearer scheme found in header");
            return null;
        }

        jwtToken = jwtToken.substring(jwtToken.toLowerCase().indexOf(BEARER_PREFIX) + BEARER_PREFIX.length());

        return jwtToken;
    }

    private void logDebug(String message, Object... args) {
        if (log.isDebugEnabled()) {
            log.debug(message, args);
        }
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
        return "apitoken_jwt";
    }

    @Override
    public boolean supportsImpersonation() {
        return false;
    }
}
