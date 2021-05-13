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

package org.opensearch.security.cache;

import java.nio.file.Path;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;

import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.user.AuthCredentials;

public class DummyHTTPAuthenticator implements HTTPAuthenticator {

    private static volatile long count;

    public DummyHTTPAuthenticator(final Settings settings, final Path configPath) {
    }

    @Override
    public String getType() {
        return "dummy";
    }

    @Override
    public AuthCredentials extractCredentials(RestRequest request, ThreadContext context) throws OpenSearchSecurityException {
        count++;
        return new AuthCredentials("dummy").markComplete();
    }

    @Override
    public boolean reRequestAuthentication(RestChannel channel, AuthCredentials credentials) {
        return false;
    }

    public static long getCount() {
        return count;
    }

    public static void reset() {
        count=0;
    }
}
