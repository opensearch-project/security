package com.amazon.dlic.auth.http.jwt.authtoken.api.authenticator;

import java.security.AccessController;
import java.security.PrivilegedAction;

import com.amazon.dlic.auth.http.jwt.authtoken.api.AuthTokenService;
import com.amazon.opendistroforelasticsearch.security.auth.HTTPAuthenticator;
import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.apache.cxf.rs.security.jose.jwt.JwtConstants;
import org.apache.cxf.rs.security.jose.jwt.JwtException;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

public class AuthTokenHttpJwtAuthenticator implements HTTPAuthenticator {

    private final static Logger log = LogManager.getLogger(AuthTokenHttpJwtAuthenticator.class);

    private final AuthTokenService authTokenService;
    private final String jwtHeaderName;
    private final String subjectKey;

    public AuthTokenHttpJwtAuthenticator(AuthTokenService authTokenService
    ) {
        this.authTokenService = authTokenService;
        this.jwtHeaderName = "Authorization";
        this.subjectKey = JwtConstants.CLAIM_SUBJECT;
    }

    @Override
    public AuthCredentials extractCredentials(RestRequest request, ThreadContext context) throws ElasticsearchSecurityException {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        return AccessController.doPrivileged((PrivilegedAction<AuthCredentials>) () -> extractCredentials0(request));

    }

    private AuthCredentials extractCredentials0(RestRequest request) throws ElasticsearchSecurityException {

        String encodedJwt = getJwtTokenString(request);

        if (Strings.isNullOrEmpty(encodedJwt)) {
            return null;
        }

        try {
            JwtToken jwt = authTokenService.getVerifiedJwtToken(encodedJwt);
            JwtClaims claims = jwt.getClaims();

            String subject = extractSubject(claims);

            if (subject == null) {
                log.error("No subject found in JWT token: " + claims);
                return null;
            }

            return AuthCredentials.forUser(subject).claims(claims.asMap()).complete().build();

        } catch (JwtException e) {
            log.info("JWT is invalid", e);
            return null;
        }

    }

    protected String getJwtTokenString(RestRequest request) {
        String authzHeader = request.header(jwtHeaderName);

        if (authzHeader == null) {
            return null;
        }

        authzHeader = authzHeader.trim();

        int separatorIndex = authzHeader.indexOf(' ');

        if (separatorIndex == -1) {
            log.info("Illegal Authorization header: " + authzHeader);
            return null;
        }

        String scheme = authzHeader.substring(0, separatorIndex);

        if (!scheme.equalsIgnoreCase("bearer")) {
            if (log.isDebugEnabled()) {
                log.debug("Unsupported authentication scheme " + scheme);
            }
            return null;
        }

        return authzHeader.substring(separatorIndex + 1).trim();
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
                log.warn("Expected type String for roles in the JWT for subject_key {}, but value was '{}' ({}). Will convert this value to String.",
                        subjectKey, subjectObject, subjectObject.getClass());
                subject = String.valueOf(subjectObject);
            } else {
                subject = (String) subjectObject;
            }
        }
        return subject;
    }




    @Override
    public boolean reRequestAuthentication(RestChannel channel, AuthCredentials authCredentials) {
        final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED, "");
        wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Bearer realm=\"Search Guard\"");
        channel.sendResponse(wwwAuthenticateResponse);
        return true;
    }


    @Override
    public String getType() {
        return "security_auth_token";
    }

}
