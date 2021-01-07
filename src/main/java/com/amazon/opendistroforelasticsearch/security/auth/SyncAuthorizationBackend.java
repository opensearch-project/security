package com.amazon.opendistroforelasticsearch.security.auth;

import java.util.Collection;
import java.util.Collections;
import java.util.function.Consumer;

import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.ElasticsearchSecurityException;

public interface SyncAuthorizationBackend extends AuthorizationBackend {
    /**
     * Populate a {@link User} with backend roles. This method will not be called for cached users.
     * <p/>
     * Add them by calling either {@code user.addRole()} or {@code user.addRoles()}
     * </P>
     * @param user The authenticated user to populate with backend roles, never null
     * @param credentials Credentials to authenticate to the authorization backend, maybe null.
     * <em>This parameter is for future usage, currently always empty credentials are passed!</em>
     * @throws ElasticsearchSecurityException in case when the authorization backend cannot be reached
     * or the {@code credentials} are insufficient to authenticate to the authorization backend.
     */
    void fillRoles(User user, AuthCredentials credentials) throws ElasticsearchSecurityException;

    default void retrieveRoles(User user, AuthCredentials credentials, Consumer<Collection<String>> onSuccess, Consumer<Exception> onFailure) {
        try {
            fillRoles(user, credentials);
            // TODO notsonice

            onSuccess.accept(Collections.emptyList());
        } catch (Exception e) {
            onFailure.accept(e);
        }
    }

}
