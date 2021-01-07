package com.amazon.dlic.auth.http.jwt.authtoken.api.authenticator;

import java.util.HashSet;
import java.util.function.Consumer;

import com.amazon.dlic.auth.http.jwt.authtoken.api.AuthTokenService;
import com.amazon.dlic.auth.http.jwt.authtoken.api.exception.InvalidTokenException;
import com.amazon.opendistroforelasticsearch.security.auth.AuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.ElasticsearchSecurityException;



public class AuthTokenAuthenticationBackend implements AuthenticationBackend {

    private AuthTokenService authTokenService;

    public AuthTokenAuthenticationBackend(AuthTokenService authTokenService) {
        this.authTokenService = authTokenService;
    }

    @Override
    public String getType() {
        return "sg_auth_token";
    }

    @Override
    public void authenticate(AuthCredentials credentials, Consumer<User> onSuccess, Consumer<Exception> onFailure) {
        try {
            authTokenService.getTokenByClaims(credentials.getClaims(), (authToken) -> {

                if (authToken.getBase().getConfigVersions() == null && authToken.getRequestedPrivileges().isTotalWildcard()) {
                    // This auth token has no restrictions and no snapshotted base. We can use the current roles. Thus, we can completely initialize the user

                    onSuccess.accept(User.forUser(authToken.getUserName()).type(AuthTokenService.USER_TYPE_FULL_CURRENT_PERMISSIONS)
                            .backendRoles(authToken.getBase().getBackendRoles()).openDistroSecurityRoles(authToken.getBase().getSearchGuardRoles())
                            .specialAuthzConfig(authToken.getId()).attributes(authToken.getBase().getAttributes()).authzComplete().build());




                } else {
                    // This auth token has restrictions or must use the snapshotted config specified in authToken.getBase().getConfigVersions()
                    // Thus, we won't initialize a "normal" User object. Rather, the user object won't contain any roles,
                    // as these would not refer to the current configuration. Code which is supposed to support auth tokens with frozen configuration,
                    // needs to use the SpecialPrivilegesEvaluationContextProvider API to retrieve the correct configuration

                    onSuccess.accept(User.forUser(authToken.getUserName())
                            .type(AuthTokenService.USER_TYPE)
                            .specialAuthzConfig(authToken.getId()).attributes(authToken.getBase().getAttributes()).authzComplete().build());
                }
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

