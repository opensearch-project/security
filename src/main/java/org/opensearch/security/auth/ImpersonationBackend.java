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

import java.util.Optional;

import org.opensearch.security.user.User;

/**
 * If an authentication backend class implements this interface, the auth type can be used for impersonation.
 */
public interface ImpersonationBackend {
    /**
     * The type (name) of the impersonation backend. Only for logging.
     */
    String getType();

    /**
     * Completes a user object based on information in an authentication backend. This is used to perform user impersonation.
     *
     * @param user The user for which the authentication backend should be queried. If the authentication backend supports
     * user attributes in combination with impersonation the attributes needs to be added to user which is returned by this method.
     *
     * @return An Optional<User>. If the user is found, Optional.isPresent() returns true, otherwise it returns false.
     */
    Optional<User> impersonate(User user);
}
