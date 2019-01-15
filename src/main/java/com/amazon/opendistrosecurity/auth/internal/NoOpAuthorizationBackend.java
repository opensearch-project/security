/*
 * Copyright 2015-2017 floragunn GmbH
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

package com.amazon.opendistrosecurity.auth.internal;

import java.nio.file.Path;

import org.elasticsearch.common.settings.Settings;

import com.amazon.opendistrosecurity.auth.AuthorizationBackend;
import com.amazon.opendistrosecurity.user.AuthCredentials;
import com.amazon.opendistrosecurity.user.User;

public class NoOpAuthorizationBackend implements AuthorizationBackend {

    public NoOpAuthorizationBackend(final Settings settings, final Path configPath) {
        super();
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
