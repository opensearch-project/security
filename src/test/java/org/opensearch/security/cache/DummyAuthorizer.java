/*
 * Copyright OpenSearch Contributors
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

package org.opensearch.security.cache;

import java.nio.file.Path;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;

import org.opensearch.security.auth.AuthorizationBackend;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;


public class DummyAuthorizer implements AuthorizationBackend {

    private static volatile long count;

    public DummyAuthorizer(final Settings settings, final Path configPath) {
    }

    @Override
    public String getType() {
        return "dummy";
    }

    @Override
    public void fillRoles(User user, AuthCredentials credentials) throws OpenSearchSecurityException {
        count++;
        user.addRole("role_" + user.getName() + "_" + System.currentTimeMillis() + "_" + count);

    }

    public static long getCount() {
        return count;
    }

    public static void reset() {
        count=0;
    }

}
