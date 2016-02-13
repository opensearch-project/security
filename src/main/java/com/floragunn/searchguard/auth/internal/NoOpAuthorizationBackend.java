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

package com.floragunn.searchguard.auth.internal;

import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.auth.AuthorizationBackend;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;

public class NoOpAuthorizationBackend implements AuthorizationBackend {

    private final Settings settings;

    public NoOpAuthorizationBackend(final Settings settings) {
        super();
        this.settings = settings;
    }

    @Override
    public String getType() {
        return "noop";
    }

    @Override
    public void fillRoles(final User user, final AuthCredentials authCreds) {
        // no-op
    }

}
