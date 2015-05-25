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

package com.floragunn.searchguard.authorization.waffle;

import java.util.HashSet;
import java.util.Set;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.os.OsUtils;
import org.elasticsearch.common.settings.Settings;

import waffle.windows.auth.IWindowsAccount;
import waffle.windows.auth.IWindowsIdentity;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authorization.NonCachingAuthorizator;

public class WaffleAuthorizator implements NonCachingAuthorizator {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    protected final Settings settings;

    @Inject
    public WaffleAuthorizator(final Settings settings) {

        this.settings = settings;

        if (!OsUtils.WINDOWS) {
            throw new ElasticsearchException("Waffle works only on Windows operating system, not on " + System.getProperty("os.name"));
        }

    }

    @Override
    public void fillRoles(final User user, final AuthCredentials optionalAuthCreds) throws AuthException {

        if (optionalAuthCreds == null || optionalAuthCreds.getNativeCredentials() == null
                || !(optionalAuthCreds.getNativeCredentials() instanceof IWindowsIdentity)) {
            throw new AuthException("Invalid authentication credentials");
        }

        final Set<String> sroles = new HashSet<String>();

        final IWindowsAccount[] roles = ((IWindowsIdentity) optionalAuthCreds.getNativeCredentials()).getGroups();
        optionalAuthCreds.clear();
        for (int i = 0; i < roles.length; i++) {
            final IWindowsAccount iWindowsAccount = roles[i];
            sroles.add(iWindowsAccount.getName());
        }

        user.addRoles(sroles);
        //return sroles;
    }

}
