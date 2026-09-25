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

package org.opensearch.security.auth.http.jwt;

import java.nio.file.Path;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.privileges.PrivilegesConfiguration;
import org.opensearch.security.user.User;

import static org.opensearch.security.dlic.rest.api.RestApiAuthorizationEvaluator.ALL_REST_ADMIN_PERMISSIONS;

public class HTTPJwtAuthenticationBackend implements AuthenticationBackend {

    public final static String JWT_AUTH_BACKEND_TYPE = "jwt";

    private PrivilegesConfiguration privilegesConfiguration;

    public HTTPJwtAuthenticationBackend(final Settings settings, final Path configPath) {}

    @Override
    public String getType() {
        return JWT_AUTH_BACKEND_TYPE;
    }

    public void setPrivilegesConfiguration(PrivilegesConfiguration privilegesConfiguration) {
        this.privilegesConfiguration = privilegesConfiguration;
    }

    @Override
    public User authenticate(final AuthenticationContext authenticationContext) throws OpenSearchSecurityException {
        if (privilegesConfiguration.privilegesEvaluator() == null) {
            throw new OpenSearchSecurityException("Backend not configured. May be OpenSearch Security is not initialized.");
        }
        final var credentials = authenticationContext.getCredentials();
        final var user = new User(
            credentials.getUsername(),
            credentials.getBackendRoles(),
            credentials.getSecurityRoles(),
            null,
            credentials.getAttributes(),
            false
        );
        validateNotRestAdmin(user);
        return user;
    }

    private void validateNotRestAdmin(final User user) {
        final var context = privilegesConfiguration.privilegesEvaluator().createContext(user, null);
        for (final var p : ALL_REST_ADMIN_PERMISSIONS) {
            if (context.getActionPrivileges().hasExplicitClusterPrivilege(context, p).isAllowed()) {
                throw new OpenSearchSecurityException(
                    "User "
                        + user.getName()
                        + " has REST API permissions. Please remove the REST API permissions to use JWT authentication."
                );
            }
        }

    }

}
