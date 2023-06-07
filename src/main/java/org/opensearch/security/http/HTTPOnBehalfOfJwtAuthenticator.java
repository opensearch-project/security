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
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.WeakKeyException;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.authtoken.jwt.EncryptionDecryptionUtil;
import org.opensearch.security.user.AuthCredentials;

public class HTTPOnBehalfOfJwtAuthenticator implements HTTPAuthenticator {

    protected final Logger log = LogManager.getLogger(this.getClass());

    private static final Pattern BEARER = Pattern.compile("^\\s*Bearer\\s.*", Pattern.CASE_INSENSITIVE);
    private static final String BEARER_PREFIX = "bearer ";

    //TODO: TO SEE IF WE NEED THE FINAL FOR FOLLOWING
    private JwtParser jwtParser;
    private String subjectKey;

    private String signingKey;
    private String encryptionKey;
    private volatile boolean initialized;

    public HTTPOnBehalfOfJwtAuthenticator() {
        super();
        init();
    }

    public HTTPOnBehalfOfJwtAuthenticator(Settings settings){
        this.signingKey = settings.get("signing_key");
        this.encryptionKey = settings.get("encryption_key");
        init();
    }

    // FOR TESTING
    public HTTPOnBehalfOfJwtAuthenticator(String signingKey, String encryptionKey){
        this.signingKey = signingKey;
        this.encryptionKey = encryptionKey;
        init();
    }

    public boolean isInitialized(){
        return initialized;
    }

    private void init() {

        try {
            if(signingKey == null || signingKey.length() == 0) {
                log.error("signingKey must not be null or empty. JWT authentication will not work");
            } else {

                signingKey = signingKey.replace("-----BEGIN PUBLIC KEY-----\n", "");
                signingKey = signingKey.replace("-----END PUBLIC KEY-----", "");

                byte[] decoded = Decoders.BASE64.decode(signingKey);
                Key key = null;

                try {
                    key = getPublicKey(decoded, "RSA");
                } catch (Exception e) {
                    log.debug("No public RSA key, try other algos ({})", e.toString());
                }

                try {
                    key = getPublicKey(decoded, "EC");
                } catch (Exception e) {
                    log.debug("No public ECDSA key, try other algos ({})", e.toString());
                }

                if(key != null) {
                    jwtParser = Jwts.parser().setSigningKey(key);
                } else {
                    jwtParser = Jwts.parser().setSigningKey(decoded);
                }

            }
        } catch (Throwable e) {
            log.error("Error while creating JWT authenticator", e);
            throw new RuntimeException(e);
        }

        subjectKey = "sub";
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
        if (jwtParser == null) {
            log.error("Missing Signing Key. JWT authentication will not work");
            return null;
        }

        String jwtToken = request.header(HttpHeaders.AUTHORIZATION);

        if (jwtToken == null || jwtToken.length() == 0) {
            if(log.isDebugEnabled()) {
                log.debug("No JWT token found in '{}' header", HttpHeaders.AUTHORIZATION);
            }
            return null;
        }

        if (!BEARER.matcher(jwtToken).matches()) {
            jwtToken = null;
        }

        final int index;
        if(jwtToken != null && (index = jwtToken.toLowerCase().indexOf(BEARER_PREFIX)) > -1) { //detect Bearer
            jwtToken = jwtToken.substring(index+BEARER_PREFIX.length());
        } else {
            if(log.isDebugEnabled()) {
                log.debug("No Bearer scheme found in header");
            }
        }

        try {
            final Claims claims = jwtParser.parseClaimsJws(jwtToken).getBody();

            final String subject = extractSubject(claims, request);

            final String audience = claims.getAudience();

            String[] roles;

            Object rolesObject = ObjectUtils.firstNonNull(claims.get("er"), claims.get("dr"));

            if (rolesObject == null) {
                log.warn(
                        "Failed to get roles from JWT claims. Check if this key is correct and available in the JWT payload.");
                roles = new String[0];
            } else {
                final String rolesClaim = rolesObject.toString();

                // Extracting roles based on the compatbility mode
                String decryptedRoles = rolesClaim;
                if (rolesObject == claims.get("er")) {
                    decryptedRoles = EncryptionDecryptionUtil.decrypt(encryptionKey, rolesClaim);
                }
                roles = Arrays.stream(decryptedRoles.split(",")).map(String::trim).toArray(String[]::new);
            }

            if (subject == null) {
                log.error("No subject found in JWT token");
                return null;
            }

            if (audience == null) {
                log.error("No audience found in JWT token");
            }

            final AuthCredentials ac = new AuthCredentials(subject, roles).markComplete();

            for(Entry<String, Object> claim: claims.entrySet()) {
                ac.addAttribute("attr.jwt."+claim.getKey(), String.valueOf(claim.getValue()));
            }

            return ac;

        } catch (WeakKeyException e) {
            System.out.println("Error MSG1!" + e.getMessage());
            log.error("Cannot authenticate user with JWT because of ", e);
            return null;
        } catch (Exception e) {
            System.out.println("Error MSG2!" + e.getMessage());
            if(log.isDebugEnabled()) {
                log.debug("Invalid or expired JWT token.", e);
            }
            return null;
        }
    }

    @Override
    public boolean reRequestAuthentication(final RestChannel channel, AuthCredentials creds) {
        return false;
    }

    @Override
    public String getType() {
        return "onbehalfof_jwt";
    }

    //TODO: Extract the audience (ext_id) and inject it into thread context

    protected String extractSubject(final Claims claims, final RestRequest request) {
        String subject = claims.getSubject();
        if(subjectKey != null) {
            // try to get roles from claims, first as Object to avoid having to catch the ExpectedTypeException
            Object subjectObject = claims.get(subjectKey, Object.class);
            if(subjectObject == null) {
                log.warn("Failed to get subject from JWT claims, check if subject_key '{}' is correct.", subjectKey);
                return null;
            }
            // We expect a String. If we find something else, convert to String but issue a warning
            if(!(subjectObject instanceof String)) {
                log.warn("Expected type String in the JWT for subject_key {}, but value was '{}' ({}). Will convert this value to String.", subjectKey, subjectObject, subjectObject.getClass());
            }
            subject = String.valueOf(subjectObject);
        }
        return subject;
    }

    private static PublicKey getPublicKey(final byte[] keyBytes, final String algo) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algo);
        return kf.generatePublic(spec);
    }

}
