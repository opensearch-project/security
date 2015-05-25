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

package com.floragunn.searchguard.authorization.simple;

import java.util.Arrays;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authorization.NonCachingAuthorizator;
import com.floragunn.searchguard.util.ConfigConstants;

public class SettingsBasedAuthorizator implements NonCachingAuthorizator {

    private final Settings settings;

    @Inject
    public SettingsBasedAuthorizator(final Settings settings) {
        this.settings = settings;
    }

    @Override
    public void fillRoles(final User user, final AuthCredentials optionalAuthCreds) throws AuthException {

        final String[] roles = settings.getAsArray(ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_SETTINGSDB_ROLES
                + user.getName());

        if (optionalAuthCreds != null) {
            optionalAuthCreds.clear();
        }

        if (roles != null) {
            user.addRoles(Arrays.asList(roles));
        }
    }
}
