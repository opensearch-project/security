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
import java.util.Optional;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.AuthCredentials;

import static java.util.function.Predicate.not;

public class HTTPProxyAuthenticator implements HTTPAuthenticator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private volatile Settings settings;
    private final Pattern rolesSeparator;

    public HTTPProxyAuthenticator(Settings settings, final Path configPath) {
        super();
        this.settings = settings;
        this.rolesSeparator = Pattern.compile(settings.get("roles_separator", ","));
    }

    @Override
    public AuthCredentials extractCredentials(final SecurityRequest request, final ThreadContext context) {

        if (context.getTransient(ConfigConstants.OPENDISTRO_SECURITY_XFF_DONE) != Boolean.TRUE) {
            throw new OpenSearchSecurityException("xff not done");
        }

        final Optional<String> requestUserHeader = Optional.ofNullable(settings.get("user_header"))
            .flatMap(userHeader -> Optional.ofNullable(request.header(userHeader)));

        final Optional<String> requestRolesHeader = Optional.ofNullable(settings.get("roles_header"))
            .flatMap(rolesHeader -> Optional.ofNullable(request.header(rolesHeader)));
        if (log.isDebugEnabled()) {
            log.debug("Headers {}", request.getHeaders());
            log.debug("UserHeader {}, value {}", settings.get("user_header"), requestUserHeader.orElse(null));
            log.debug("RolesHeader {}, value {}", settings.get("roles_header"), requestRolesHeader.orElse(null));
        }

        return requestUserHeader.map(userHeader -> {
            final String[] backendRoles = requestRolesHeader.map(
                rolesHeader -> rolesSeparator.splitAsStream(rolesHeader)
                    .map(String::trim)
                    .filter(not(String::isEmpty))
                    .toArray(String[]::new)
            ).orElse(null);
            return new AuthCredentials(userHeader, backendRoles).markComplete();
        }).orElseGet(() -> {
            log.trace("No '{}' header, send 401", settings.get("user_header"));
            return null;
        });
    }

    @Override
    public Optional<SecurityResponse> reRequestAuthentication(final SecurityRequest response, AuthCredentials creds) {
        return Optional.empty();
    }

    @Override
    public String getType() {
        return "proxy";
    }
}
