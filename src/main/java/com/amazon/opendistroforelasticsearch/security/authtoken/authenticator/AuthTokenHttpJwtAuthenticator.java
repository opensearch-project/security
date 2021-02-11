package com.amazon.opendistroforelasticsearch.security.authtoken.authenticator;

import java.nio.file.Path;

import com.amazon.dlic.auth.http.jwt.AbstractHTTPJwtAuthenticator;
import com.amazon.dlic.auth.http.jwt.keybyoidc.KeyProvider;
import com.amazon.opendistroforelasticsearch.security.authtoken.AuthTokenService;
import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.apache.cxf.rs.security.jose.jwt.JwtConstants;
import org.apache.cxf.rs.security.jose.jwt.JwtException;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;

public class AuthTokenHttpJwtAuthenticator extends AbstractHTTPJwtAuthenticator {

    private final static Logger log = LogManager.getLogger(AuthTokenHttpJwtAuthenticator.class);

    private AuthTokenService authTokenService;

    public AuthTokenHttpJwtAuthenticator(final Settings settings, final Path configPath) {
        super(settings, configPath);
        setAuthenticatorSettings("Authorization", JwtConstants.CLAIM_SUBJECT);
    }

    public void setAuthTokenService(AuthTokenService authTokenService) {
        this.authTokenService = authTokenService;
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
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    @Override
    protected KeyProvider initKeyProvider(Settings settings, Path configPath) throws Exception {
        return null;
    }

    @Override
    public String getType() {
        return "opendistro_security_auth_token";
    }
}
