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

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.List;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.security.WeakKeyException;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.authtoken.jwt.EncryptionDecryptionUtil;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.KeyUtils;

import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.util.AuthTokenUtils.isAccessToRestrictedEndpoints;

public class OnBehalfOfAuthenticator implements HTTPAuthenticator {

    private static final String REGEX_PATH_PREFIX = "/(" + LEGACY_OPENDISTRO_PREFIX + "|" + PLUGINS_PREFIX + ")/" + "(.*)";
    private static final Pattern PATTERN_PATH_PREFIX = Pattern.compile(REGEX_PATH_PREFIX);

    protected final Logger log = LogManager.getLogger(this.getClass());

    private static final Pattern BEARER = Pattern.compile("^\\s*Bearer\\s.*", Pattern.CASE_INSENSITIVE);
    private static final String BEARER_PREFIX = "bearer ";

    private final JwtParser jwtParser;
    private final String encryptionKey;
    private final Boolean oboEnabled;
    private final String clusterName;

    private final EncryptionDecryptionUtil encryptionUtil;

    public OnBehalfOfAuthenticator(Settings settings, String clusterName) {
        String oboEnabledSetting = settings.get("enabled", "true");
        oboEnabled = Boolean.parseBoolean(oboEnabledSetting);
        encryptionKey = settings.get("encryption_key");
        JwtParserBuilder builder = initParserBuilder(settings.get("signing_key"));
        jwtParser = builder.build();

        this.clusterName = clusterName;
        this.encryptionUtil = new EncryptionDecryptionUtil(encryptionKey);
    }

    private JwtParserBuilder initParserBuilder(final String signingKey) {
        JwtParserBuilder jwtParserBuilder = KeyUtils.createJwtParserBuilderFromSigningKey(signingKey, log);

        if (jwtParserBuilder == null) {
            throw new OpenSearchSecurityException("Unable to find on behalf of authenticator signing key");
        }

        return jwtParserBuilder;
    }

    private List<String> extractSecurityRolesFromClaims(Claims claims) {
        Object er = claims.get("er");
        Object dr = claims.get("dr");
        String rolesClaim = "";

        if (er != null) {
            rolesClaim = encryptionUtil.decrypt(er.toString());
        } else if (dr != null) {
            rolesClaim = dr.toString();
        } else {
            log.warn("This is a malformed On-behalf-of Token");
        }

        List<String> roles = Arrays.stream(rolesClaim.split(","))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .collect(Collectors.toUnmodifiableList());

        return roles;
    }

    private String[] extractBackendRolesFromClaims(Claims claims) {
        Object backendRolesObject = claims.get("br");
        String[] backendRoles;

        if (backendRolesObject == null) {
            backendRoles = new String[0];
        } else {
            // Extracting roles based on the compatibility mode
            backendRoles = Arrays.stream(backendRolesObject.toString().split(",")).map(String::trim).toArray(String[]::new);
        }

        return backendRoles;
    }

    @Override
    @SuppressWarnings("removal")
    public AuthCredentials extractCredentials(RestRequest request, ThreadContext context) throws OpenSearchSecurityException {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        AuthCredentials creds = AccessController.doPrivileged(new PrivilegedAction<AuthCredentials>() {
            @Override
            public AuthCredentials run() {
                return extractCredentials0(request);
            }
        });

        return creds;
    }

    private AuthCredentials extractCredentials0(final RestRequest request) {
        if (!oboEnabled) {
            log.error("On-behalf-of authentication is disabled");
            return null;
        }

        if (jwtParser == null) {
            log.error("Missing Signing Key. JWT authentication will not work");
            return null;
        }

        String jwtToken = extractJwtFromHeader(request);
        if (jwtToken == null) {
            return null;
        }

        if (!isRequestAllowed(request)) {
            return null;
        }

        try {
            final Claims claims = jwtParser.parseClaimsJws(jwtToken).getBody();

            final String subject = claims.getSubject();
            if (subject == null) {
                log.error("Valid jwt on behalf of token with no subject");
                return null;
            }

            final String audience = claims.getAudience();
            if (audience == null) {
                log.error("Valid jwt on behalf of token with no audience");
                return null;
            }

            final String issuer = claims.getIssuer();
            if (!clusterName.equals(issuer)) {
                log.error("The issuer of this OBO does not match the current cluster identifier");
                return null;
            }

            List<String> roles = extractSecurityRolesFromClaims(claims);
            String[] backendRoles = extractBackendRolesFromClaims(claims);

            final AuthCredentials ac = new AuthCredentials(subject, roles, backendRoles).markComplete();

            for (Entry<String, Object> claim : claims.entrySet()) {
                ac.addAttribute("attr.jwt." + claim.getKey(), String.valueOf(claim.getValue()));
            }

            return ac;

        } catch (WeakKeyException e) {
            log.error("Cannot authenticate user with JWT because of ", e);
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid or expired JWT token.", e);
            }
        }

        // Return null for the authentication failure
        return null;
    }

    private String extractJwtFromHeader(RestRequest request) {
        String jwtToken = request.header(HttpHeaders.AUTHORIZATION);

        if (jwtToken == null || jwtToken.isEmpty()) {
            logDebug("No JWT token found in '{}' header", HttpHeaders.AUTHORIZATION);
            return null;
        }

        if (!BEARER.matcher(jwtToken).matches()) {
            return null;
        }

        if (jwtToken.toLowerCase().contains(BEARER_PREFIX)) {
            jwtToken = jwtToken.substring(jwtToken.toLowerCase().indexOf(BEARER_PREFIX) + BEARER_PREFIX.length());
        } else {
            logDebug("No Bearer scheme found in header");
            return null;
        }

        return jwtToken;
    }

    private void logDebug(String message, Object... args) {
        if (log.isDebugEnabled()) {
            log.debug(message, args);
        }
    }

    public Boolean isRequestAllowed(final RestRequest request) {
        Matcher matcher = PATTERN_PATH_PREFIX.matcher(request.path());
        final String suffix = matcher.matches() ? matcher.group(2) : null;
        if (isAccessToRestrictedEndpoints(request, suffix)) {
            final OpenSearchException exception = ExceptionUtils.invalidUsageOfOBOTokenException();
            log.error(exception.toString());
            return false;
        }
        return true;
    }

    @Override
    public boolean reRequestAuthentication(final RestChannel channel, AuthCredentials creds) {
        return false;
    }

    @Override
    public String getType() {
        return "onbehalfof_jwt";
    }

}
