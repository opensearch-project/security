package com.amazon.opendistroforelasticsearch.security.auth;

import java.util.function.Consumer;

import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.ElasticsearchSecurityException;

public interface SyncAuthenticationBackend extends AuthenticationBackend {

    /**
     * Validate credentials and return an authenticated user (or throw an ElasticsearchSecurityException)
     * <p/>
     * Results of this method are normally cached so that we not need to query the backend for every authentication attempt.
     * <p/>
     * @param The credentials to be validated, never null
     * @return the authenticated User, never null
     * @throws ElasticsearchSecurityException in case an authentication failure
     * (when credentials are incorrect, the user does not exist or the backend is not reachable)
     */
    User authenticate(AuthCredentials credentials) throws ElasticsearchSecurityException;

    /**
     * Validate credentials and return an authenticated user (or throw an ElasticsearchSecurityException)
     * <p/>
     * Results of this method are normally cached so that we not need to query the backend for every authentication attempt.
     * <p/>
     * @param The credentials to be validated, never null
     * @return the authenticated User, never null
     * @throws ElasticsearchSecurityException in case an authentication failure
     * (when credentials are incorrect, the user does not exist or the backend is not reachable)
     */
    default void authenticate(AuthCredentials credentials, Consumer<User> onSuccess, Consumer<Exception> onFailure) {
        try {
            User user = this.authenticate(credentials);
            onSuccess.accept(user);
        } catch (Exception e) {
            onFailure.accept(e);
        }
    }
}

