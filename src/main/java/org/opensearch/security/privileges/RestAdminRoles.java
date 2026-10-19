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

package org.opensearch.security.privileges;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

/**
 * The roles listed in {@code plugins.security.restapi.roles_enabled}. A caller holding at least one of them is a
 * REST admin and may use the Security REST API.
 */
public final class RestAdminRoles {

    private final Set<String> roles;

    public RestAdminRoles(final Settings settings) {
        this.roles = Set.copyOf(settings.getAsList(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED));
    }

    /**
     * @return true if the mapped roles contain at least one REST admin role (exact match)
     */
    public boolean matches(final Collection<String> mappedRoles) {
        return mappedRoles != null && !Collections.disjoint(roles, mappedRoles);
    }

    /**
     * @return true if no REST admin roles are configured
     */
    public boolean isEmpty() {
        return roles.isEmpty();
    }

    /**
     * @return the configured REST admin roles
     */
    public Set<String> roles() {
        return roles;
    }
}
