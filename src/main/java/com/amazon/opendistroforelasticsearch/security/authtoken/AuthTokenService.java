package com.amazon.opendistroforelasticsearch.security.authtoken;

import com.amazon.opendistroforelasticsearch.security.authtoken.config.AuthTokenServiceConfig;
import org.apache.cxf.rs.security.jose.jwt.JwtException;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;

import java.util.Map;
public class AuthTokenService {

    public static final String USER_TYPE = "opendistro_security_auth_token";
    public static final String USER_TYPE_FULL_CURRENT_PERMISSIONS = "opendistro_security_auth_token_full_current_permissions";

    public AuthTokenService() {
    }

    public void setConfig(AuthTokenServiceConfig config) {
    }

    public AuthToken getTokenByClaims(Map<String, Object> claims) {
        return null;
    }

    public JwtToken createToken() {
        return null;
    }

    public JwtToken getVerifiedJwtToken(String encodedJwt) throws JwtException {
        return null;
    }
}
