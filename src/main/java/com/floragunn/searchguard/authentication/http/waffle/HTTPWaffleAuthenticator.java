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

package com.floragunn.searchguard.authentication.http.waffle;

import java.net.InetSocketAddress;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.os.OsUtils;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import waffle.windows.auth.IWindowsAuthProvider;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.IWindowsSecurityContext;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.AuthenticationBackend;
import com.floragunn.searchguard.authentication.http.HTTPAuthenticator;
import com.floragunn.searchguard.authorization.Authorizator;
import com.google.common.base.Joiner;
import com.google.common.io.BaseEncoding;

public class HTTPWaffleAuthenticator implements HTTPAuthenticator {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Settings settings;

    private final IWindowsAuthProvider authProvider;

    @Inject
    public HTTPWaffleAuthenticator(final Settings settings, final IWindowsAuthProvider authProvider) {
        this.settings = settings;

        this.authProvider = authProvider;

        if (!OsUtils.WINDOWS) {
            throw new ElasticsearchException("Waffle works only on Windows operating system, not on " + System.getProperty("os.name"));
        }

    }

    @Override
    public User authenticate(final RestRequest request, final RestChannel channel, final AuthenticationBackend backend,
            final Authorizator authorizator) throws AuthException {

        final AuthorizationHeader authorizationHeader = new AuthorizationHeader(request);

        if (authorizationHeader.isNull()) {

            final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED);
            wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Negotiate");
            wwwAuthenticateResponse.addHeader("WWW-Authenticate", "NTLM");
            channel.sendResponse(wwwAuthenticateResponse);
            return null;

        }

        final boolean ntlmPost = authorizationHeader.isNtlmType1PostAuthorizationHeader();

        // maintain a connection-based session for NTLM tokens
        final InetSocketAddress address = ((InetSocketAddress) request.getRemoteAddress());
        final String connectionId = Joiner.on(":").useForNull("").join(address.getHostName(), address.getPort());
        final String securityPackage = authorizationHeader.getSecurityPackage();
        log.trace("security package: {}, connection id: {}", securityPackage, connectionId);

        if (ntlmPost) {
            // type 2 NTLM authentication message received
            log.trace("This is a Ntlm Type 1 Post Authorization Header");
            authProvider.resetSecurityToken(connectionId);
        }

        final byte[] tokenBuffer = authorizationHeader.getTokenBytes();
        log.trace("token buffer: {} byte(s)", Integer.valueOf(tokenBuffer.length));
        final IWindowsSecurityContext securityContext = authProvider.acceptSecurityToken(connectionId, tokenBuffer, securityPackage);

        final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED);

        final byte[] continueTokenBytes = securityContext.getToken();
        if (continueTokenBytes != null && continueTokenBytes.length > 0) {
            final String continueToken = BaseEncoding.base64().encode(continueTokenBytes);
            log.trace("continue token: {}", continueToken);
            wwwAuthenticateResponse.addHeader("WWW-Authenticate", securityPackage + " " + continueToken);
        }

        log.trace("continue required: {}", Boolean.valueOf(securityContext.isContinue()));
        if (securityContext.isContinue() || ntlmPost) {

            wwwAuthenticateResponse.addHeader("Connection", "keep-alive");
            channel.sendResponse(wwwAuthenticateResponse);
            return null;
        }

        final IWindowsIdentity identity = securityContext.getIdentity();
        securityContext.dispose();

        final User authenticatedUser = backend.authenticate(new AuthCredentials(identity.getFqn(), identity));

        //authorizator must accept  IWindowsIdentity
        authorizator.fillRoles(authenticatedUser, (new AuthCredentials(identity.getFqn(), identity)));

        log.debug("User '{}' is authenticated", authenticatedUser);

        return authenticatedUser;
    }

}
