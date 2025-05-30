/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.auth;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.opensearch.security.user.AuthCredentials;

/**
 * This class allows HTTPAuthenticators and authentication backends to provide context data to authorization backends.
 * This is especially useful for siblings of authentication backends and authorization backends (like LDAP authc and
 * LDAP authz) to pass data which is specific to the auth type (like the LDAP user entry).
 * <p>
 * This allows to abolish specialized sub-classes of the User object (like LdapUser).
 */
public class AuthenticationContext {
    private final AuthCredentials credentials;
    private final Map<Class<?>, Object> contextData = new HashMap<>();

    public AuthenticationContext(AuthCredentials credentials) {
        this.credentials = credentials;
    }

    public <T> void addContextData(Class<T> contextDataType, T contextDataObject) {
        this.contextData.put(contextDataType, contextDataObject);
    }

    public <T> Optional<T> getContextData(Class<T> contextDataType) {
        @SuppressWarnings("unchecked")
        T result = (T) this.contextData.get(contextDataType);
        return Optional.ofNullable(result);
    }

    public AuthCredentials getCredentials() {
        return credentials;
    }
}
