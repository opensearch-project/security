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

package com.floragunn.searchguard.authentication.backend.waffle;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.os.OsUtils;
import org.elasticsearch.common.settings.Settings;

import waffle.windows.auth.IWindowsAuthProvider;
import waffle.windows.auth.IWindowsIdentity;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.AuthenticationBackend;
import com.floragunn.searchguard.util.ConfigConstants;

public class WaffleAuthenticationBackend implements AuthenticationBackend {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Settings settings;
    protected final boolean stripDomain;

    private final IWindowsAuthProvider authProvider;

    @Inject
    public WaffleAuthenticationBackend(final Settings settings, final IWindowsAuthProvider authProvider) {
        this.settings = settings;

        this.authProvider = authProvider;
        stripDomain = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_AUTHENTICATION_WAFFLE_STRIP_DOMAIN, true);

        if (!OsUtils.WINDOWS) {
            throw new ElasticsearchException("Waffle works only on Windows operating system, not on " + System.getProperty("os.name"));
        }

    }

    @Override
    public User authenticate(final AuthCredentials credentials) throws AuthException {
        //TODO FUTURE check login waffle
        final String[] domainUsername = credentials.getUsername().split("\\");

        try {
            final IWindowsIdentity identity = authProvider.logonDomainUser(domainUsername[1], domainUsername[0],
                    new String(credentials.getPassword()));

            if (identity == null) {
                throw new AuthException("Cannot authenticate, windows identity is null");
            }

            //String domain = authProvider.getCurrentComputer().getMemberOf()
            String authenticatedUser = identity.getFqn();
            if (stripDomain) {
                final int index = authenticatedUser.indexOf("\\");
                if (index > -1) {
                    authenticatedUser = authenticatedUser.substring(index + 1);
                }
            }
            return new User(authenticatedUser);
        } catch (final Exception e) {
            throw new AuthException(e);
        } finally {
            credentials.clear();
        }
    }

}