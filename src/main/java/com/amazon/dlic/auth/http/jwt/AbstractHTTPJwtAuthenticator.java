/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import java.security.PrivilegedAction;
import java.util.Collection;
import java.util.Map.Entry;

import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.amazon.dlic.auth.http.jwt.keybyoidc.AuthenticatorUnavailableException;
import com.amazon.dlic.auth.http.jwt.keybyoidc.BadCredentialsException;
import com.amazon.dlic.auth.http.jwt.keybyoidc.JwtVerifier;
import com.amazon.dlic.auth.http.jwt.keybyoidc.KeyProvider;
import com.amazon.opendistroforelasticsearch.security.auth.HTTPAuthenticator;
import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;

public abstract class AbstractHTTPJwtAuthenticator implements HTTPAuthenticator {
    private final static Logger log = LogManager.getLogger(AbstractHTTPJwtAuthenticator.class);

    private static final String BEARER = "bearer ";

    private KeyProvider keyProvider;
    private JwtVerifier jwtVerifier;
    private final String jwtHeaderName;
    private final String jwtUrlParameter;
    private final String subjectKey;
    private final String rolesKey;

    public AbstractHTTPJwtAuthenticator(Settings settings, Path configPath) {
        jwtUrlParameter = settings.get("jwt_url_parameter");
        jwtHeaderName = settings.get("jwt_header", "Authorization");
        rolesKey = settings.get("roles_key");
        subjectKey = settings.get("subject_key");

        try {
            this.keyProvider = this.initKeyProvider(settings, configPath);

            jwtVerifier = new JwtVerifier(keyProvider);

        } catch (Exception e) {
            log.error("Error creating JWT authenticator: " + e + ". JWT authentication will not work", e);
        }
    }

    @Override
    public AuthCredentials extractCredentials(RestRequest request, ThreadContext context)
            throws ElasticsearchSecurityException {
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

    private AuthCredentials extractCredentials0(final RestRequest request) throws ElasticsearchSecurityException {

        String jwtString = getJwtTokenString(request);

        if (Strings.isNullOrEmpty(jwtString)) {
            return null;
        }

        JwtToken jwt;

        try {
            jwt = jwtVerifier.getVerifiedJwtToken(jwtString);
        } catch (AuthenticatorUnavailableException e) {
            log.info(e);
            throw new ElasticsearchSecurityException(e.getMessage(), RestStatus.SERVICE_UNAVAILABLE);
        } catch (BadCredentialsException e) {
            log.info("Extracting JWT token from " + jwtString + " failed", e);
            return null;
        }

        JwtClaims claims = jwt.getClaims();

        final String subject = extractSubject(claims);

        if (subject == null) {
            log.error("No subject found in JWT token");
            return null;
        }

        final String[] roles = extractRoles(claims);

        final AuthCredentials ac = new AuthCredentials(subject, roles).markComplete();

        for (Entry<String, Object> claim : claims.asMap().entrySet()) {
            ac.addAttribute("attr.jwt." + claim.getKey(), String.valueOf(claim.getValue()));
        }

        return ac;

    }

    protected String getJwtTokenString(RestRequest request) {
        String jwtToken = request.header(jwtHeaderName);

        if (jwtUrlParameter != null) {
            if (jwtToken == null || jwtToken.isEmpty()) {
                jwtToken = request.param(jwtUrlParameter);
            } else {
                // just consume to avoid "contains unrecognized parameter"
                request.param(jwtUrlParameter);
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

    protected String extractSubject(JwtClaims claims) {
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
                        subjectKey, subjectObject, subjectObject.getClass());
                subject = String.valueOf(subjectObject);
            } else {
                subject = (String) subjectObject;
            }
        }
        return subject;
    }

    @SuppressWarnings("unchecked")
    protected String[] extractRoles(JwtClaims claims) {
        if (rolesKey == null) {
            return new String[0];
        }

        Object rolesObject = claims.getClaim(rolesKey);

        if (rolesObject == null) {
            log.warn(
                    "Failed to get roles from JWT claims with roles_key '{}'. Check if this key is correct and available in the JWT payload.",
                    rolesKey);
            return new String[0];
        }

        String[] roles = String.valueOf(rolesObject).split(",");

        // We expect a String or Collection. If we find something else, convert to
        // String but issue a warning
        if (!(rolesObject instanceof String) && !(rolesObject instanceof Collection<?>)) {
            log.warn(
                    "Expected type String or Collection for roles in the JWT for roles_key {}, but value was '{}' ({}). Will convert this value to String.",
                    rolesKey, rolesObject, rolesObject.getClass());
        } else if (rolesObject instanceof Collection<?>) {
            roles = ((Collection<String>) rolesObject).toArray(new String[0]);
        }

        for (int i = 0; i < roles.length; i++) {
            roles[i] = roles[i].trim();
        }

        return roles;
    }

    protected abstract KeyProvider initKeyProvider(Settings settings, Path configPath) throws Exception;

    @Override
    public boolean reRequestAuthentication(RestChannel channel, AuthCredentials authCredentials) {
        final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED, "");
        wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Bearer realm=\"Open Distro Security\"");
        channel.sendResponse(wwwAuthenticateResponse);
        return true;
    }

}
