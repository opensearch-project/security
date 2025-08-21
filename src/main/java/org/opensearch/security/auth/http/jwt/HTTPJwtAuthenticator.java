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

package org.opensearch.security.auth.http.jwt;

import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.logging.DeprecationLogger;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.KeyUtils;

import com.nimbusds.jwt.proc.BadJWTException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.security.WeakKeyException;

import static org.apache.http.HttpHeaders.AUTHORIZATION;

public class HTTPJwtAuthenticator implements HTTPAuthenticator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final DeprecationLogger deprecationLog = DeprecationLogger.getLogger(this.getClass());

    private static final Pattern BASIC = Pattern.compile("^\\s*Basic\\s.*", Pattern.CASE_INSENSITIVE);
    private static final String BEARER = "bearer ";

    private final List<JwtParser> jwtParsers = new ArrayList<>();
    private final String jwtHeaderName;
    private final boolean isDefaultAuthHeader;
    private final String jwtUrlParameter;
    private final List<String> rolesKey;
    private final List<String> subjectKey;
    private final List<String> requiredAudience;
    private final String requireIssuer;
    private final int clockSkewToleranceSeconds;

    @SuppressWarnings("removal")
    public HTTPJwtAuthenticator(final Settings settings, final Path configPath) {
        super();

        List<String> signingKeys = settings.getAsList("signing_key");

        jwtUrlParameter = settings.get("jwt_url_parameter");
        jwtHeaderName = settings.get("jwt_header", AUTHORIZATION);
        isDefaultAuthHeader = AUTHORIZATION.equalsIgnoreCase(jwtHeaderName);
        rolesKey = settings.getAsList("roles_key");
        subjectKey = settings.getAsList("subject_key");
        requiredAudience = settings.getAsList("required_audience");
        requireIssuer = settings.get("required_issuer");
        clockSkewToleranceSeconds = settings.getAsInt(
            "jwt_clock_skew_tolerance_seconds",
            AbstractHTTPJwtAuthenticator.DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS
        );

        if (!jwtHeaderName.equals(AUTHORIZATION)) {
            deprecationLog.deprecate(
                "jwt_header",
                "The 'jwt_header' setting will be removed in the next major version of OpenSearch.  Consult https://github.com/opensearch-project/security/issues/3886 for more details."
            );
        }

        for (String key : signingKeys) {
            JwtParser jwtParser;
            final JwtParserBuilder jwtParserBuilder = KeyUtils.createJwtParserBuilderFromSigningKey(key, log);
            if (jwtParserBuilder == null) {
                jwtParser = null;
            } else {
                if (requireIssuer != null) {
                    jwtParserBuilder.requireIssuer(requireIssuer);
                }

                jwtParserBuilder.clockSkewSeconds(clockSkewToleranceSeconds);

                final SecurityManager sm = System.getSecurityManager();
                if (sm != null) {
                    sm.checkPermission(new SpecialPermission());
                }
                jwtParser = AccessController.doPrivileged((PrivilegedAction<JwtParser>) jwtParserBuilder::build);
            }
            jwtParsers.add(jwtParser);
        }
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
                return extractCredentials0(request);
            }
        });

        return creds;
    }

    private AuthCredentials extractCredentials0(final SecurityRequest request) {

        if (jwtParsers.isEmpty() || jwtParsers.getFirst() == null) {
            log.error("Missing Signing Key. JWT authentication will not work");
            return null;
        }

        String jwtToken = request.header(jwtHeaderName);
        log.warn("JWT token: {}", jwtToken);
        log.warn("with basic HTTPHandler")
        if (isDefaultAuthHeader && jwtToken != null && BASIC.matcher(jwtToken).matches()) {
            jwtToken = null;
        }

        if ((jwtToken == null || jwtToken.isEmpty()) && jwtUrlParameter != null) {
            jwtToken = request.params().get(jwtUrlParameter);
        } else {
            // just consume to avoid "contains unrecognized parameter"
            request.params().get(jwtUrlParameter);
        }

        if (jwtToken == null || jwtToken.length() == 0) {
            if (log.isDebugEnabled()) {
                log.debug(
                    "No JWT token found in '{}' {} header",
                    jwtUrlParameter == null ? jwtHeaderName : jwtUrlParameter,
                    jwtUrlParameter == null ? "header" : "url parameter"
                );
            }
            return null;
        }

        final int index;
        if ((index = jwtToken.toLowerCase().indexOf(BEARER)) > -1) { // detect Bearer
            jwtToken = jwtToken.substring(index + BEARER.length());
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No Bearer scheme found in header");
            }
        }

        for (JwtParser jwtParser : jwtParsers) {
            try {

                final Claims claims = jwtParser.parseClaimsJws(jwtToken).getBody();

                if (!requiredAudience.isEmpty()) {
                    assertValidAudienceClaim(claims);
                }

                final String subject = extractSubject(claims);

                if (subject == null) {
                    log.error("No subject found in JWT token");
                    return null;
                }

                final String[] roles = extractRoles(claims);

                final AuthCredentials ac = new AuthCredentials(subject, roles).markComplete();

                for (Entry<String, Object> claim : claims.entrySet()) {
                    String key = "attr.jwt." + claim.getKey();
                    Object value = claim.getValue();

                    if (value instanceof Collection<?>) {
                        try {
                            // Convert the list to a JSON array string
                            String jsonValue = DefaultObjectMapper.writeValueAsString(value, false);
                            ac.addAttribute(key, jsonValue);
                        } catch (Exception e) {
                            log.warn("Failed to convert list claim to JSON for key: " + key, e);
                            // Fallback to string representation
                            ac.addAttribute(key, String.valueOf(value));
                        }
                    } else {
                        ac.addAttribute(key, String.valueOf(value));
                    }
                }

                return ac;

            } catch (WeakKeyException e) {
                log.error("Cannot authenticate user with JWT because of ", e);
                return null;
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid or expired JWT token.", e);
                }
            }
        }
        log.debug("Unable to authenticate JWT Token with any configured signing key");
        return null;
    }

    private void assertValidAudienceClaim(Claims claims) throws BadJWTException {
        if (requiredAudience.isEmpty()) {
            return;
        }

        if (Collections.disjoint(claims.getAudience(), requiredAudience)) {
            throw new BadJWTException("Claim of 'aud' doesn't contain any required audience.");
        }
    }

    @Override
    public Optional<SecurityResponse> reRequestAuthentication(final SecurityRequest channel, AuthCredentials creds) {
        return Optional.of(
            new SecurityResponse(HttpStatus.SC_UNAUTHORIZED, Map.of("WWW-Authenticate", "Bearer realm=\"OpenSearch Security\""), "")
        );
    }

    @Override
    public Set<String> getSensitiveUrlParams() {
        if (jwtUrlParameter != null) {
            return Set.of(jwtUrlParameter);
        }
        return Collections.emptySet();
    }

    @Override
    public String getType() {
        return "jwt";
    }

    protected String extractSubject(final Claims claims) {
        String subject = claims.getSubject();
        if (subjectKey != null && !subjectKey.isEmpty()) {
            // ── 1. Traverse the nested structure ───────────────────────────────────────
            Object node = claims;                                        // start at root
            for (String key : subjectKey) {
                if (!(node instanceof Map<?, ?> map)) {                  // unexpected shape
                    log.warn(
                        "While following subject_key path {}, expected a JSON object before '{}', but found '{}' ({}).",
                        subjectKey,
                        key,
                        node,
                        node.getClass()
                    );
                    return null;  // Subject cannot be extracted from the configured path
                }
                node = map.get(key);
                if (node == null) {                                      // key missing
                    log.warn("Failed to find '{}' in JWT claims while following subject_key path {}.", key, subjectKey);
                    return null;  // Subject cannot be extracted from the configured path
                }
            }
            // ── 2. Interpret the leaf value ────────────────────────────────────────────
            if (node instanceof String str) {
                return str.trim();
            } else {                                                     // something odd
                log.warn(
                    "Expected a String at the end of subject_key path {}, but found '{}' ({}). Converting to String.",
                    subjectKey,
                    node,
                    node.getClass()
                );
                return String.valueOf(node).trim();
            }

        }
        return subject;
    }

    @SuppressWarnings("unchecked")
    protected String[] extractRoles(final Claims claims) {

        // Nothing configured → nothing to extract
        if (rolesKey == null || rolesKey.isEmpty()) {
            return new String[0];
        }

        // ── 1. Traverse the nested structure ───────────────────────────────────────
        Object node = claims;                                        // start at root
        for (String key : rolesKey) {
            if (!(node instanceof Map<?, ?> map)) {                  // unexpected shape
                log.warn(
                    "While following roles_key path {}, expected a JSON object before '{}', " + "but found '{}' ({}).",
                    rolesKey,
                    key,
                    node,
                    node.getClass()
                );
                return new String[0];
            }
            node = map.get(key);
            if (node == null) {                                      // key missing
                log.warn("Failed to find '{}' in JWT claims while following roles_key path {}.", key, rolesKey);
                return new String[0];
            }
        }

        // ── 2. Interpret the leaf value ────────────────────────────────────────────
        Set<String> collected = new LinkedHashSet<>();               // dedupe + keep order

        if (node instanceof String str) {
            Arrays.stream(str.split(","))                            // "admin,dev"
                .map(String::trim)
                .filter(Predicate.not(String::isEmpty))
                .forEach(collected::add);

        } else if (node instanceof Collection<?> col) {
            col.stream()
                .filter(Objects::nonNull)
                .map(Object::toString)
                .map(String::trim)
                .filter(Predicate.not(String::isEmpty))
                .forEach(collected::add);

        } else {                                                     // something odd
            log.warn(
                "Expected a String or Collection at the end of roles_key path {}, " + "but found '{}' ({}). Converting to String.",
                rolesKey,
                node,
                node.getClass()
            );
            collected.add(node.toString().trim());
        }

        return collected.toArray(new String[0]);
    }

}
