/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.dlic.auth.http.jwt;

import java.nio.file.Path;
import java.security.AccessController;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import org.apache.http.HttpHeaders;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestStatus;

import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.user.AuthCredentials;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.WeakKeyException;

public class HTTPJwtAuthenticator implements HTTPAuthenticator {

    protected final Logger log = LogManager.getLogger(this.getClass());

    private static final Pattern BASIC = Pattern.compile("^\\s*Basic\\s.*", Pattern.CASE_INSENSITIVE);
    private static final String BEARER = "bearer ";

    private final JwtParser jwtParser;
    private final String jwtHeaderName;
    private final boolean isDefaultAuthHeader;
    private final String jwtUrlParameter;
    private final String rolesKey;
    private final String subjectKey;

    public HTTPJwtAuthenticator(final Settings settings, final Path configPath) {
        super();

        JwtParser _jwtParser = null;

        try {
            String signingKey = settings.get("signing_key");

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
                    _jwtParser = Jwts.parser().setSigningKey(key);
                } else {
                    _jwtParser = Jwts.parser().setSigningKey(decoded);
                }

            }
        } catch (Throwable e) {
            log.error("Error creating JWT authenticator. JWT authentication will not work", e);
            throw new RuntimeException(e);
        }

        jwtUrlParameter = settings.get("jwt_url_parameter");
        jwtHeaderName = settings.get("jwt_header", HttpHeaders.AUTHORIZATION);
        isDefaultAuthHeader = HttpHeaders.AUTHORIZATION.equalsIgnoreCase(jwtHeaderName);
        rolesKey = settings.get("roles_key");
        subjectKey = settings.get("subject_key");
        jwtParser = _jwtParser;
    }


    @Override
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

        String jwtToken = request.header(jwtHeaderName);
        if (isDefaultAuthHeader && jwtToken != null && BASIC.matcher(jwtToken).matches()) {
            jwtToken = null;
        }

        if((jwtToken == null || jwtToken.isEmpty()) && jwtUrlParameter != null) {
            jwtToken = request.param(jwtUrlParameter);
        } else {
            //just consume to avoid "contains unrecognized parameter"
            request.param(jwtUrlParameter);
        }

        if (jwtToken == null || jwtToken.length() == 0) {
            if(log.isDebugEnabled()) {
                log.debug("No JWT token found in '{}' {} header", jwtUrlParameter==null?jwtHeaderName:jwtUrlParameter, jwtUrlParameter==null?"header":"url parameter");
            }
            return null;
        }

        final int index;
        if((index = jwtToken.toLowerCase().indexOf(BEARER)) > -1) { //detect Bearer
            jwtToken = jwtToken.substring(index+BEARER.length());
        } else {
            if(log.isDebugEnabled()) {
                log.debug("No Bearer scheme found in header");
            }
        }

        try {
            final Claims claims = jwtParser.parseClaimsJws(jwtToken).getBody();

            final String subject = extractSubject(claims, request);

            if (subject == null) {
            	log.error("No subject found in JWT token");
            	return null;
            }

            final String[] roles = extractRoles(claims, request);

            final AuthCredentials ac = new AuthCredentials(subject, roles).markComplete();

            for(Entry<String, Object> claim: claims.entrySet()) {
                ac.addAttribute("attr.jwt."+claim.getKey(), String.valueOf(claim.getValue()));
            }

            return ac;

        } catch (WeakKeyException e) {
            log.error("Cannot authenticate user with JWT because of ", e);
            return null;
        } catch (Exception e) {
            if(log.isDebugEnabled()) {
                log.debug("Invalid or expired JWT token.", e);
            }
            return null;
        }
    }

    @Override
    public boolean reRequestAuthentication(final RestChannel channel, AuthCredentials creds) {
        final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED,"");
        wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Bearer realm=\"OpenSearch Security\"");
        channel.sendResponse(wwwAuthenticateResponse);
        return true;
    }

    @Override
    public String getType() {
        return "jwt";
    }

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
        		log.warn("Expected type String for roles in the JWT for subject_key {}, but value was '{}' ({}). Will convert this value to String.", subjectKey, subjectObject, subjectObject.getClass());
            }
            subject = String.valueOf(subjectObject);
        }
        return subject;
    }

    @SuppressWarnings("unchecked")
    protected String[] extractRoles(final Claims claims, final RestRequest request) {
    	// no roles key specified
    	if(rolesKey == null) {
    		return new String[0];
    	}
		// try to get roles from claims, first as Object to avoid having to catch the ExpectedTypeException
    	final Object rolesObject = claims.get(rolesKey, Object.class);
    	if(rolesObject == null) {
    		log.warn("Failed to get roles from JWT claims with roles_key '{}'. Check if this key is correct and available in the JWT payload.", rolesKey);
    		return new String[0];
    	}

    	String[] roles = String.valueOf(rolesObject).split(",");

    	// We expect a String or Collection. If we find something else, convert to String but issue a warning
    	if (!(rolesObject instanceof String) && !(rolesObject instanceof Collection<?>)) {
    		log.warn("Expected type String or Collection for roles in the JWT for roles_key {}, but value was '{}' ({}). Will convert this value to String.", rolesKey, rolesObject, rolesObject.getClass());
		} else if (rolesObject instanceof Collection<?>) {
		    roles = ((Collection<String>) rolesObject).toArray(new String[0]);
		}

    	for (int i = 0; i < roles.length; i++) {
    	    roles[i] = roles[i].trim();
    	}

    	return roles;
    }

    private static PublicKey getPublicKey(final byte[] keyBytes, final String algo) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algo);
        return kf.generatePublic(spec);
    }

}
