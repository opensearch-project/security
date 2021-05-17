/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.cache;

import java.nio.file.Path;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;

import com.amazon.opendistroforelasticsearch.security.auth.AuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.auth.AuthorizationBackend;
import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import com.amazon.opendistroforelasticsearch.security.user.User;


public class DummyAuthenticationBackend implements AuthenticationBackend {

    private static volatile long authCount;
    private static volatile long existsCount;

    public DummyAuthenticationBackend(final Settings settings, final Path configPath) {
    }

    @Override
    public String getType() {
        return "dummy";
    }

    @Override
    public User authenticate(AuthCredentials credentials) throws OpenSearchSecurityException {
        authCount++;
        return new User(credentials.getUsername());
    }

    @Override
    public boolean exists(User user) {
        existsCount++;
        return true;
    }

    public static long getAuthCount() {
        return authCount;
    }

    public static long getExistsCount() {
        return existsCount;
    }

    public static void reset() {
        authCount=0;
        existsCount=0;
    }
}