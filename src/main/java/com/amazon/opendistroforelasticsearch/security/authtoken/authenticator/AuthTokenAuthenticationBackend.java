package com.amazon.opendistroforelasticsearch.security.authtoken.authenticator;

import com.amazon.opendistroforelasticsearch.security.auth.AuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.authtoken.AuthTokenService;
import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.common.settings.Settings;

import java.nio.file.Path;

public class AuthTokenAuthenticationBackend implements AuthenticationBackend {

    private AuthTokenService authTokenService;

    public AuthTokenAuthenticationBackend(final Settings settings, final Path configPath) {
    }

    public AuthTokenAuthenticationBackend(AuthTokenService authTokenService) {
        this.authTokenService = authTokenService;
    }

    @Override
    public String getType() {
        return "opendistro_security_auth_token";
    }

    @Override
    public User authenticate(AuthCredentials credentials) {
        return null;
    }

    @Override
    public boolean exists(User user) {
        // This is only related to impersonation. Auth tokens don't support impersonation.
        return false;
    }

   /* @Override
    public UserCachingPolicy userCachingPolicy() {
        return UserCachingPolicy.NEVER;
    }*/

}
