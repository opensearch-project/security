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

package com.floragunn.searchguard.authentication.http.clientcert;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.http.netty.NettyHttpRequest;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.AuthenticationBackend;
import com.floragunn.searchguard.authentication.http.HTTPAuthenticator;
import com.floragunn.searchguard.authorization.Authorizator;
import com.floragunn.searchguard.http.netty.MutualSSLHandler.DefaultHttpsRequest;
import com.floragunn.searchguard.util.ConfigConstants;

public class HTTPSClientCertAuthenticator implements HTTPAuthenticator {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Settings settings;

    @Inject
    public HTTPSClientCertAuthenticator(final Settings settings) {
        this.settings = settings;
    }

    @SuppressWarnings("restriction")
    @Override
    public User authenticate(final RestRequest request, final RestChannel channel, final AuthenticationBackend backend,
            final Authorizator authorizator) throws AuthException {

        String dn = null;

        sun.security.x509.X500Name x500Principal = null;
        try {
            final NettyHttpRequest nettyRequest = (NettyHttpRequest) request;
            final DefaultHttpsRequest httpsRequest = (DefaultHttpsRequest) nettyRequest.request();
            x500Principal = (sun.security.x509.X500Name) httpsRequest.getPrincipal();
            dn = String.valueOf(x500Principal);// request.header(MutualSSLHandler.SEARCHGUARD_MUTUAL_SSL_AUTH);
        } catch (final Exception e) {
            log.error("Invalid request or invalid principal. Pls. check settings, this authenticater works only with https/ssl", e);
        }

        if (dn == null || dn.isEmpty() || dn.equals("null")) {
            throw new AuthException("No x500 principal found in request");
        }

        final String userAttribute = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_HTTPS_CLIENTCERT_ATTRIBUTENAME, "cn")
                .toLowerCase();
        final int index = dn.toLowerCase().indexOf(userAttribute + "=");
        String userName = dn;
        if (index > -1) {
            final int start = index + userAttribute.length() + 1;
            userName = dn.substring(start, dn.indexOf(",", start));
        }

        final User authenticatedUser = backend.authenticate(new AuthCredentials(userName, x500Principal));
        authorizator.fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName(), x500Principal));

        log.debug("User '{}' is authenticated", authenticatedUser);

        return authenticatedUser;
    }

}
