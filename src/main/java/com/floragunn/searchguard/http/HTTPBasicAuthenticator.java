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

package com.floragunn.searchguard.http;

import java.nio.charset.StandardCharsets;

import javax.xml.bind.DatatypeConverter;

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.floragunn.searchguard.auth.HTTPAuthenticator;
import com.floragunn.searchguard.user.AuthCredentials;

//TODO FUTURE allow only if protocol==https
public class HTTPBasicAuthenticator implements HTTPAuthenticator {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Settings settings;

    public HTTPBasicAuthenticator(final Settings settings) {
        super();
        this.settings = settings;
    }

    @Override
    public AuthCredentials authenticate(final RestRequest request, final RestChannel channel) {

        final String authorizationHeader = request.header("Authorization");
        final boolean forceLogin = request.paramAsBoolean("force_login", false);

        if (authorizationHeader != null && !forceLogin) {
            if (!authorizationHeader.trim().toLowerCase().startsWith("basic ")) {
                log.warn("No 'Basic Authorization' header, send 401 and 'WWW-Authenticate Basic'");
                requestAuthentication(channel);
                return null;
            } else {

                final String decodedBasicHeader = new String(DatatypeConverter.parseBase64Binary(authorizationHeader.split(" ")[1]),
                        StandardCharsets.UTF_8);

                final int index = decodedBasicHeader.lastIndexOf(':');

                String username = null;
                String password = null;

                if (index > 0 && decodedBasicHeader.length() - 1 != index) {
                    username = decodedBasicHeader.substring(0, index);
                    password = decodedBasicHeader.substring(index + 1);
                }

                if (username == null || password == null) {
                    log.warn("Invalid 'Authorization' header, send 401 and 'WWW-Authenticate Basic'");
                    requestAuthentication(channel);
                    return null;
                } else {
                    return new AuthCredentials(username, password.toCharArray());
                }
            }
        } else {
            log.trace("No 'Authorization' header, send 401 and 'WWW-Authenticate Basic'");
            requestAuthentication(channel);
            return null;
        }
    }

    @Override
    public void requestAuthentication(final RestChannel channel) {
        final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED);
        wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Basic realm=\"Search Guard\"");
        channel.sendResponse(wwwAuthenticateResponse);
    }

    @Override
    public String getType() {
        return "basic";
    }
}
