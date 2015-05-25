/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.authentication.http;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.AuthenticationBackend;
import com.floragunn.searchguard.authorization.Authorizator;

public class HTTPUnauthenticatedAuthenticator implements HTTPAuthenticator {

    private static final String UNAUTHENTICATED_USER = "searchguard_unauthenticated_user";
    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Settings settings;

    @Inject
    public HTTPUnauthenticatedAuthenticator(final Settings settings) {
        this.settings = settings;
    }

    @Override
    public User authenticate(final RestRequest request, final RestChannel channel, final AuthenticationBackend backend,
            final Authorizator authorizator) throws AuthException {

        final User authenticatedUser = backend
                .authenticate(new AuthCredentials(HTTPUnauthenticatedAuthenticator.UNAUTHENTICATED_USER, null));

        authorizator.fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName(), null));

        log.debug("User '{}' is authenticated", authenticatedUser);

        return authenticatedUser;

    }

}
