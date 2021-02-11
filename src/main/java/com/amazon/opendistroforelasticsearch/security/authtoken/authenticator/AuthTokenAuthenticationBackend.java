package com.amazon.opendistroforelasticsearch.security.authtoken.authenticator;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.function.Consumer;

import com.amazon.opendistroforelasticsearch.security.auth.AuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.authtoken.AuthTokenService;
import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;

public class AuthTokenAuthenticationBackend implements AuthenticationBackend {

    private static final Logger log = LogManager.getLogger(AuthTokenAuthenticationBackend.class);

    private AuthTokenService authTokenService;

    public AuthTokenAuthenticationBackend(final Settings settings, final Path configPath) {
    }

    public void setAuthTokenService(AuthTokenService authTokenService) {
        this.authTokenService = authTokenService;
    }

    @Override
    public String getType() {
        return "opendistro_security_auth_token";
    }

    @Override
    public void authenticate(AuthCredentials credentials, Consumer<User> onSuccess, Consumer<Exception> onFailure) {
    }

    @Override
    public boolean exists(User user) {
        // This is only related to impersonation. Auth tokens don't support impersonation.
        return false;
    }

    @Override
    public UserCachingPolicy userCachingPolicy() {
        return UserCachingPolicy.NEVER;
    }

}
