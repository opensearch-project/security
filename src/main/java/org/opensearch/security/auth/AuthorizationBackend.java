/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.security.user.User;

/**
 * OpenSearch Security custom authorization backends need to implement this interface.
 * <p/>
 * Authorization backends populate a prior authenticated {@link User} with backend roles who's the user is a member of.
 * <p/>
 * Implementation classes must provide a public constructor
 * <p/>
 * {@code public MyHTTPAuthenticator(org.opensearch.common.settings.Settings settings, java.nio.file.Path configPath)}
 * <p/>
 * The constructor should not throw any exception in case of an initialization problem.
 * Instead catch all exceptions and log a appropriate error message. A logger can be instantiated like:
 * <p/>
 * {@code private final Logger log = LogManager.getLogger(this.getClass());}
 *
 * <p/>
 */
public interface AuthorizationBackend {

    /**
     * The type (name) of the authorizer. Only for logging.
     * @return the type
     */
    String getType();

    /**
     * This method is called during the auth phase to add additional backend roles to a  {@link User}. This method will not be called for cached users.
     * <p>
     * Implementations must use the withRoles() method and return the newly created User object.
     *
     * @param user The authenticated user to populate with backend roles, never null
     * @param context Context data specific to the request that is currently processed.
     * @throws OpenSearchSecurityException in case when the authorization backend cannot be reached
     * or the {@code credentials} are insufficient to authenticate to the authorization backend.
     */
    User addRoles(User user, AuthenticationContext context) throws OpenSearchSecurityException;

}
