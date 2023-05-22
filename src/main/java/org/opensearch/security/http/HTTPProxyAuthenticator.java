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
import java.util.regex.Pattern;

import com.google.common.base.Predicates;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.Strings;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.AuthCredentials;

public class HTTPProxyAuthenticator implements HTTPAuthenticator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private volatile Settings settings;
    private final Pattern rolesSeparator;

    public HTTPProxyAuthenticator(Settings settings, final Path configPath) {
        super();
        this.settings = settings;
        this.rolesSeparator =  Pattern.compile(settings.get("roles_separator", ","));
    }

    @Override
    public AuthCredentials extractCredentials(final RestRequest request, ThreadContext context) {
    	
        if(context.getTransient(ConfigConstants.OPENDISTRO_SECURITY_XFF_DONE) !=  Boolean.TRUE) {
            throw new OpenSearchSecurityException("xff not done");
        }
        
        final String userHeader = settings.get("user_header");
        final String rolesHeader = settings.get("roles_header");
        
        if (log.isDebugEnabled()) {
            log.debug("Headers {}", request.getHeaders());
            log.debug("UserHeader {}, value {}", userHeader, userHeader == null ? null : request.header(userHeader));
            log.debug("RolesHeader {}, value {}", rolesHeader, rolesHeader == null ? null : request.header(rolesHeader));
        }

        if (!Strings.isNullOrEmpty(userHeader) && !Strings.isNullOrEmpty((String) request.header(userHeader))) {

            String[] backendRoles = null;

            if (!Strings.isNullOrEmpty(rolesHeader) && !Strings.isNullOrEmpty((String) request.header(rolesHeader))) {
                backendRoles = rolesSeparator
                        .splitAsStream((String) request.header(rolesHeader))
                        .map(String::trim)
                        .filter(Predicates.not(String::isEmpty))
                        .toArray(String[]::new);
            }
            return new AuthCredentials((String) request.header(userHeader), backendRoles).markComplete();
        } else {
            log.trace("No '{}' header, send 401", userHeader);
            return null;
        }
    }

    @Override
    public boolean reRequestAuthentication(final RestChannel channel, AuthCredentials creds) {
        return false;
    }

    @Override
    public String getType() {
        return "proxy";
    }
}
