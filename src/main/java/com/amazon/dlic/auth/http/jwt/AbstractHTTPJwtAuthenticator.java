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
import java.security.PrivilegedAction;
import java.text.ParseException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.regex.Pattern;

import com.google.common.annotations.VisibleForTesting;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.logging.DeprecationLogger;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.Strings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.user.AuthCredentials;

import com.amazon.dlic.auth.http.jwt.keybyoidc.AuthenticatorUnavailableException;
import com.amazon.dlic.auth.http.jwt.keybyoidc.BadCredentialsException;
import com.amazon.dlic.auth.http.jwt.keybyoidc.JwtVerifier;
import com.amazon.dlic.auth.http.jwt.keybyoidc.KeyProvider;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import static org.apache.http.HttpHeaders.AUTHORIZATION;

public abstract class AbstractHTTPJwtAuthenticator implements HTTPAuthenticator {
    private final static Logger log = LogManager.getLogger(AbstractHTTPJwtAuthenticator.class);
    private final static DeprecationLogger deprecationLog = DeprecationLogger.getLogger(AbstractHTTPJwtAuthenticator.class);

    private static final String BEARER = "bearer ";
    private static final Pattern BASIC = Pattern.compile("^\\s*Basic\\s.*", Pattern.CASE_INSENSITIVE);

    private KeyProvider keyProvider;
    private JwtVerifier jwtVerifier;
    private final String jwtHeaderName;
    private final boolean isDefaultAuthHeader;
    private final String jwtUrlParameter;
    private final String subjectKey;
    private final String rolesKey;
    private final List<String> requiredAudience;
    private final String requiredIssuer;

    public static final int DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS = 30;
    private final int clockSkewToleranceSeconds;

    public AbstractHTTPJwtAuthenticator(Settings settings, Path configPath) {
        jwtUrlParameter = settings.get("jwt_url_parameter");
        jwtHeaderName = settings.get("jwt_header", AUTHORIZATION);
        isDefaultAuthHeader = AUTHORIZATION.equalsIgnoreCase(jwtHeaderName);
        rolesKey = settings.get("roles_key");
        subjectKey = settings.get("subject_key");
        clockSkewToleranceSeconds = settings.getAsInt("jwt_clock_skew_tolerance_seconds", DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS);
        requiredAudience = settings.getAsList("required_audience");
        requiredIssuer = settings.get("required_issuer");

        if (!jwtHeaderName.equals(AUTHORIZATION)) {
            deprecationLog.deprecate(
                "jwt_header",
                "The 'jwt_header' setting will be removed in the next major version of OpenSearch.  Consult https://github.com/opensearch-project/security/issues/3886 for more details."
            );
        }

        try {
            this.keyProvider = this.initKeyProvider(settings, configPath);
            jwtVerifier = new JwtVerifier(keyProvider, clockSkewToleranceSeconds, requiredIssuer, requiredAudience);

        } catch (Exception e) {
            log.error("Error creating JWT authenticator. JWT authentication will not work", e);
            throw new RuntimeException(e);
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

    private AuthCredentials extractCredentials0(final SecurityRequest request) throws OpenSearchSecurityException {

        String jwtString = getJwtTokenString(request);

        if (Strings.isNullOrEmpty(jwtString)) {
            return null;
        }

        SignedJWT jwt;
        JWTClaimsSet claimsSet;

        try {
            jwt = jwtVerifier.getVerifiedJwtToken(jwtString);
            claimsSet = jwt.getJWTClaimsSet();
        } catch (AuthenticatorUnavailableException e) {
            log.info(e.toString());
            throw new OpenSearchSecurityException(e.getMessage(), RestStatus.SERVICE_UNAVAILABLE);
        } catch (BadCredentialsException | ParseException e) {
            if (log.isTraceEnabled()) {
                log.trace("Extracting JWT token from {} failed", jwtString, e);
            }
            return null;
        }

        final String subject = extractSubject(claimsSet);
        if (subject == null) {
            log.error("No subject found in JWT token");
            return null;
        }

        final String[] roles = extractRoles(claimsSet);
        final AuthCredentials ac = new AuthCredentials(subject, roles).markComplete();

        for (Entry<String, Object> claim : claimsSet.getClaims().entrySet()) {
            ac.addAttribute("attr.jwt." + claim.getKey(), String.valueOf(claim.getValue()));
        }

        return ac;
    }

    protected String getJwtTokenString(SecurityRequest request) {
        String jwtToken = request.header(jwtHeaderName);
        if (isDefaultAuthHeader && jwtToken != null && BASIC.matcher(jwtToken).matches()) {
            jwtToken = null;
        }

        if (jwtUrlParameter != null) {
            if (jwtToken == null || jwtToken.isEmpty()) {
                jwtToken = request.params().get(jwtUrlParameter);
            } else {
                // just consume to avoid "contains unrecognized parameter"
                request.params().get(jwtUrlParameter);
            }
        }

        if (jwtToken == null) {
            return null;
        }

        int index;

        if ((index = jwtToken.toLowerCase().indexOf(BEARER)) > -1) { // detect Bearer
            jwtToken = jwtToken.substring(index + BEARER.length());
        }

        return jwtToken;
    }

    @VisibleForTesting
    public String extractSubject(JWTClaimsSet claims) {
        String subject = claims.getSubject();

        if (subjectKey != null) {
            Object subjectObject = claims.getClaim(subjectKey);

            if (subjectObject == null) {
                log.warn("Failed to get subject from JWT claims, check if subject_key '{}' is correct.", subjectKey);
                return null;
            }

            // We expect a String. If we find something else, convert to String but issue a
            // warning
            if (!(subjectObject instanceof String)) {
                log.warn(
                    "Expected type String for roles in the JWT for subject_key {}, but value was '{}' ({}). Will convert this value to String.",
                    subjectKey,
                    subjectObject,
                    subjectObject.getClass()
                );
                subject = String.valueOf(subjectObject);
            } else {
                subject = (String) subjectObject;
            }
        }
        return subject;
    }

    @SuppressWarnings("unchecked")
    @VisibleForTesting
    public String[] extractRoles(JWTClaimsSet claims) {
        if (rolesKey == null) {
            return new String[0];
        }

        Object rolesObject = claims.getClaim(rolesKey);

        if (rolesObject == null) {
            log.warn(
                "Failed to get roles from JWT claims with roles_key '{}'. Check if this key is correct and available in the JWT payload.",
                rolesKey
            );
            return new String[0];
        }

        String[] roles = String.valueOf(rolesObject).split(",");

        // We expect a String or Collection. If we find something else, convert to
        // String but issue a warning
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

        return roles;
    }

    protected abstract KeyProvider initKeyProvider(Settings settings, Path configPath) throws Exception;

    @Override
    public Optional<SecurityResponse> reRequestAuthentication(final SecurityRequest request, AuthCredentials authCredentials) {
        return Optional.of(
            new SecurityResponse(HttpStatus.SC_UNAUTHORIZED, Map.of("WWW-Authenticate", "Bearer realm=\"OpenSearch Security\""), "")
        );
    }

    public List<String> getRequiredAudience() {
        return requiredAudience;
    }

    public String getRequiredIssuer() {
        return requiredIssuer;
    }

}
