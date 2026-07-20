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

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;

import org.apache.hc.core5.http.HttpHeaders;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.authtoken.jwt.EncryptionDecryptionUtil;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.KeyUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.WeakKeyException;

public class OnBehalfOfAuthenticator implements HTTPAuthenticator {

    private static final int MINIMUM_SIGNING_KEY_BIT_LENGTH = 512;
    private static final String SIGNING_KEY = "signing_key";
    private static final String ENCRYPTION_KEY = "encryption_key";

    protected final Logger log = LogManager.getLogger(this.getClass());

    private static final Pattern BEARER = Pattern.compile("^\\s*Bearer\\s.*", Pattern.CASE_INSENSITIVE);
    private static final String BEARER_PREFIX = "bearer ";

    private final Settings settings;
    private final Boolean enabled;
    private final String clusterName;
    private final Path configPath;
    private volatile boolean initialized = false;
    private volatile JwtParser jwtParser;
    private volatile EncryptionDecryptionUtil encryptionUtil;

    public OnBehalfOfAuthenticator(Settings settings, String clusterName, Path configPath) {
        this.enabled = settings.getAsBoolean("enabled", Boolean.TRUE);
        this.settings = settings;
        this.clusterName = clusterName;
        this.configPath = configPath;
    }

    /**
     * Builds the JWT parser and encryption helper on first use. Initialization is attempted exactly once.
     *
     * @return {@code true} if OBO authentication is usable, {@code false} if it is misconfigured
     */
    private synchronized boolean ensureInitialized() {
        if (!initialized) {
            initialized = true;
            try {
                jwtParser = AccessController.doPrivileged(this::buildJwtParser);
                encryptionUtil = EncryptionDecryptionUtil.fromSettings(settings, ENCRYPTION_KEY, configPath);
            } catch (final RuntimeException e) {
                log.error("On-behalf-of authentication is misconfigured; OBO tokens will be rejected: {}", e.toString(), e);
            }
        }
        return jwtParser != null;
    }

    /**
     * Builds the HMAC verification parser. The signing key may be supplied either via a keystore (e.g. BCFKS,
     * keeping the key out of cluster state) or as a Base64-encoded {@code signing_key} setting. The keystore
     * path mirrors how {@link org.opensearch.security.authtoken.jwt.JwtVendor} signs OBO tokens, so issuance
     * and verification share the same key material.
     */
    private JwtParser buildJwtParser() {
        final SecretKey keystoreKey = KeyUtils.loadKeyFromKeystore(settings, SIGNING_KEY, configPath);
        if (keystoreKey != null) {
            final byte[] keyBytes = keystoreKey.getEncoded();
            validateSigningKeyBitLength(keyBytes.length * Byte.SIZE);
            return Jwts.parser().verifyWith(Keys.hmacShaKeyFor(keyBytes)).build();
        }
        final String signingKey = settings.get(SIGNING_KEY);
        validateSigningKey(signingKey);
        return KeyUtils.createJwtParserBuilderFromSigningKey(signingKey, log).build();
    }

    /**
     * Validates a Base64-encoded {@code signing_key}, throwing {@link OpenSearchSecurityException} with a
     * descriptive message when it is missing, not valid Base64, or below the
     * {@value #MINIMUM_SIGNING_KEY_BIT_LENGTH}-bit minimum. Package-private static so it can be unit-tested
     * directly without standing up an authenticator.
     */
    static void validateSigningKey(final String signingKey) {
        if (signingKey == null) {
            throw new OpenSearchSecurityException("Unable to find on behalf of authenticator signing_key");
        }
        final int signingKeyLengthBits;
        try {
            signingKeyLengthBits = Base64.getDecoder().decode(signingKey).length * Byte.SIZE;
        } catch (final IllegalArgumentException e) {
            throw new OpenSearchSecurityException("Signing key is not a valid Base64-encoded value: " + e.getMessage());
        }
        validateSigningKeyBitLength(signingKeyLengthBits);
    }

    static void validateSigningKeyBitLength(final int signingKeyLengthBits) {
        if (signingKeyLengthBits < MINIMUM_SIGNING_KEY_BIT_LENGTH) {
            throw new OpenSearchSecurityException(
                "Signing key size was "
                    + signingKeyLengthBits
                    + " bits, which is not secure enough. Please use a signing_key with a size >= "
                    + MINIMUM_SIGNING_KEY_BIT_LENGTH
                    + " bits."
            );
        }
    }

    private List<String> extractSecurityRolesFromClaims(Claims claims) {
        Object er = claims.get("encrypted_roles");
        if (er == null) {
            er = claims.get("er"); // backward compatibility
        }
        Object dr = claims.get("roles");
        if (dr == null) {
            dr = claims.get("dr"); // backward compatibility
        }
        String rolesClaim = "";

        if (er != null) {
            if (encryptionUtil == null) {
                log.error("OBO token contains encrypted roles ('er') but no encryption_key is configured");
                return List.of();
            }
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
        Object backendRolesObject = claims.get("backend_roles");
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
    public AuthCredentials extractCredentials(final SecurityRequest request, final ThreadContext context)
        throws OpenSearchSecurityException {
        AuthCredentials creds = AccessController.doPrivileged(() -> extractCredentials0(request));

        return creds;
    }

    private AuthCredentials extractCredentials0(final SecurityRequest request) {
        if (!enabled) {
            log.debug("On-behalf-of authentication is disabled");
            return null;
        }

        String jwtToken = extractJwtFromHeader(request);
        if (jwtToken == null || !ensureInitialized()) {
            return null;
        }

        try {
            final Claims claims = jwtParser.parseClaimsJws(jwtToken).getBody();

            final String subject = claims.getSubject();
            if (subject == null) {
                log.error("Valid jwt on behalf of token with no subject");
                return null;
            }

            final Set<String> audience = claims.getAudience();
            if (audience == null || audience.isEmpty()) {
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

    @Override
    public Optional<SecurityResponse> reRequestAuthentication(final SecurityRequest response, AuthCredentials creds) {
        return Optional.empty();
    }

    @Override
    public String getType() {
        return "onbehalfof_jwt";
    }

    @Override
    public boolean supportsImpersonation() {
        return false;
    }
}
