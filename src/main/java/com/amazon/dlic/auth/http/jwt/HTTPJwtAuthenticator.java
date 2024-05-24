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

package com.amazon.dlic.auth.http.jwt;

import java.nio.file.Path;
import java.security.AccessController;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.logging.DeprecationLogger;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
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

    private final JwtParser jwtParser;
    private final String jwtHeaderName;
    private final boolean isDefaultAuthHeader;
    private final String jwtUrlParameter;
    private final String rolesKey;
    private final String subjectKey;
    private final List<String> requiredAudience;
    private final String requireIssuer;

    public HTTPJwtAuthenticator(final Settings settings, final Path configPath) {
        super();

        String signingKey = settings.get("signing_key");
        jwtUrlParameter = settings.get("jwt_url_parameter");
        jwtHeaderName = settings.get("jwt_header", AUTHORIZATION);
        isDefaultAuthHeader = AUTHORIZATION.equalsIgnoreCase(jwtHeaderName);
        rolesKey = settings.get("roles_key");
        subjectKey = settings.get("subject_key");
        requiredAudience = settings.getAsList("required_audience");
        requireIssuer = settings.get("required_issuer");

        if (!jwtHeaderName.equals(AUTHORIZATION)) {
            deprecationLog.deprecate(
                "jwt_header",
                "The 'jwt_header' setting will be removed in the next major version of OpenSearch.  Consult https://github.com/opensearch-project/security/issues/3886 for more details."
            );
        }

        final JwtParserBuilder jwtParserBuilder = KeyUtils.createJwtParserBuilderFromSigningKey(signingKey, log);
        if (jwtParserBuilder == null) {
            jwtParser = null;
        } else {
            if (requireIssuer != null) {
                jwtParserBuilder.requireIssuer(requireIssuer);
            }

            final SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }
            jwtParser = AccessController.doPrivileged((PrivilegedAction<JwtParser>) jwtParserBuilder::build);
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
        if (jwtParser == null) {
            log.error("Missing Signing Key. JWT authentication will not work");
            return null;
        }

        String jwtToken = request.header(jwtHeaderName);
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

        try {
            final Claims claims = jwtParser.parseClaimsJws(jwtToken).getBody();

            if (!requiredAudience.isEmpty()) {
                assertValidAudienceClaim(claims);
            }

            final String subject = extractSubject(claims, request);

            if (subject == null) {
                log.error("No subject found in JWT token");
                return null;
            }

            final String[] roles = extractRoles(claims, request);

            final AuthCredentials ac = new AuthCredentials(subject, roles).markComplete();

            for (Entry<String, Object> claim : claims.entrySet()) {
                ac.addAttribute("attr.jwt." + claim.getKey(), String.valueOf(claim.getValue()));
            }

            return ac;

        } catch (WeakKeyException e) {
            log.error("Cannot authenticate user with JWT because of ", e);
            return null;
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid or expired JWT token.", e);
            }
            return null;
        }
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

    protected String extractSubject(final Claims claims, final SecurityRequest request) {
        String subject = claims.getSubject();
        if (subjectKey != null) {
            // try to get roles from claims, first as Object to avoid having to catch the ExpectedTypeException
            Object subjectObject = claims.get(subjectKey, Object.class);
            if (subjectObject == null) {
                log.warn("Failed to get subject from JWT claims, check if subject_key '{}' is correct.", subjectKey);
                return null;
            }
            // We expect a String. If we find something else, convert to String but issue a warning
            if (!(subjectObject instanceof String)) {
                log.warn(
                    "Expected type String for roles in the JWT for subject_key {}, but value was '{}' ({}). Will convert this value to String.",
                    subjectKey,
                    subjectObject,
                    subjectObject.getClass()
                );
            }
            subject = String.valueOf(subjectObject);
        }
        return subject;
    }

    @SuppressWarnings("unchecked")
    protected String[] extractRoles(final Claims claims, final SecurityRequest request) {
        // no roles key specified
        if (rolesKey == null) {
            return new String[0];
        }
        // try to get roles from claims, first as Object to avoid having to catch the ExpectedTypeException
        final Object rolesObject = claims.get(rolesKey, Object.class);
        if (rolesObject == null) {
            log.warn(
                "Failed to get roles from JWT claims with roles_key '{}'. Check if this key is correct and available in the JWT payload.",
                rolesKey
            );
            return new String[0];
        }

        String[] roles = String.valueOf(rolesObject).split(",");

        // We expect a String or Collection. If we find something else, convert to String but issue a warning
        if (!(rolesObject instanceof String) && !(rolesObject instanceof Collection<?>)) {
            log.warn(
                "Expected type String or Collection for roles in the JWT for roles_key {}, but value was '{}' ({}). Will convert this value to String.",
                rolesKey,
                rolesObject,
                rolesObject.getClass()
            );
        } else if (rolesObject instanceof Collection<?>) {
            roles = ((Collection<String>) rolesObject).toArray(new String[0]);
        }

        for (int i = 0; i < roles.length; i++) {
            roles[i] = roles[i].trim();
        }

        return roles;
    }

    private static PublicKey getPublicKey(final byte[] keyBytes, final String algo) throws NoSuchAlgorithmException,
        InvalidKeySpecException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algo);
        return kf.generatePublic(spec);
    }

}
