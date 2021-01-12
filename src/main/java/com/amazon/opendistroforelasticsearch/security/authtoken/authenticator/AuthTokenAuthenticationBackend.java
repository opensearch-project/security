package com.amazon.opendistroforelasticsearch.security.authtoken.authenticator;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.function.Consumer;

import com.amazon.opendistroforelasticsearch.security.auth.AuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.authtoken.AuthTokenService;
import com.amazon.opendistroforelasticsearch.security.authtoken.validation.InvalidTokenException;
import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
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
        try {
            authTokenService.getTokenByClaims(credentials.getClaims(), (authToken) -> {

                onSuccess.accept(User.forUser(authToken.getUserName())
                        .type(AuthTokenService.USER_TYPE_FULL_CURRENT_PERMISSIONS)
                        .specialAuthzConfig(authToken.getId())
                        .authzComplete()
                        .build());

            }, (noSuchAuthTokenException) -> {
                onFailure.accept(new ElasticsearchSecurityException(noSuchAuthTokenException.getMessage(), noSuchAuthTokenException));
            }, (e) -> {
                onFailure.accept(e);
            });

        } catch (InvalidTokenException e) {
            onFailure.accept(new ElasticsearchSecurityException(e.getMessage(), e));
        } catch (Exception e) {
            onFailure.accept(e);
        }
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

