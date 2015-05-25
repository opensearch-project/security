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

package com.floragunn.searchguard.authentication.http.proxy;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.AuthenticationBackend;
import com.floragunn.searchguard.authentication.http.HTTPAuthenticator;
import com.floragunn.searchguard.authorization.Authorizator;
import com.floragunn.searchguard.util.ConfigConstants;

public class HTTPProxyAuthenticator implements HTTPAuthenticator {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Settings settings;

    @Inject
    public HTTPProxyAuthenticator(final Settings settings) {
        this.settings = settings;
    }

    @Override
    public User authenticate(final RestRequest request, final RestChannel channel, final AuthenticationBackend backend,
            final Authorizator authorizator) throws AuthException {
        final String headerName = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_PROXY_HEADER, "X-Authenticated-User");
        final List<String> trustedSourceIps = Arrays.asList(settings.getAsArray(
                ConfigConstants.SEARCHGUARD_AUTHENTICATION_PROXY_TRUSTED_IPS, new String[0]));

        if (!trustedSourceIps.contains("*")
                && !trustedSourceIps.contains(((InetSocketAddress) request.getRemoteAddress()).getAddress().getHostAddress())) {
            throw new AuthException("source ip not trusted");
        }

        final String proxyUser = request.header(headerName);

        if (proxyUser == null || proxyUser.isEmpty()) {
            throw new AuthException("no or empty " + headerName + " header");
        }

        final User authenticatedUser = backend.authenticate(new AuthCredentials(proxyUser, null));
        authorizator.fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName(), null));

        log.debug("User '{}' is authenticated", authenticatedUser);

        return authenticatedUser;
    }

}
