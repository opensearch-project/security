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

package org.opensearch.security.http;

import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.support.HTTPHelper;
import org.opensearch.security.user.AuthCredentials;

//TODO FUTURE allow only if protocol==https
public class HTTPBasicAuthenticator implements HTTPAuthenticator {

    protected final Logger log = LogManager.getLogger(this.getClass());

    public HTTPBasicAuthenticator(final Settings settings, final Path configPath) {

    }

    @Override
    public AuthCredentials extractCredentials(final SecurityRequest request, final ThreadContext threadContext) {

        final boolean forceLogin = Boolean.getBoolean(request.params().get("force_login"));

        if (forceLogin) {
            return null;
        }

        final String authorizationHeader = request.header("Authorization");

        return HTTPHelper.extractCredentials(authorizationHeader, log);
    }

    @Override
    public Optional<SecurityResponse> reRequestAuthentication(final SecurityRequest request, AuthCredentials creds) {
        return Optional.of(
            new SecurityResponse(
                HttpStatus.SC_UNAUTHORIZED,
                Map.of("WWW-Authenticate", "Basic realm=\"OpenSearch Security\""),
                "Unauthorized"
            )
        );
    }

    @Override
    public String getType() {
        return "basic";
    }
}
