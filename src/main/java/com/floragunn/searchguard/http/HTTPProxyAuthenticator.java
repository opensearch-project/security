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

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.floragunn.searchguard.action.configupdate.TransportConfigUpdateAction;
import com.floragunn.searchguard.auth.HTTPAuthenticator;
import com.floragunn.searchguard.configuration.ConfigChangeListener;
import com.floragunn.searchguard.user.AuthCredentials;

public class HTTPProxyAuthenticator implements HTTPAuthenticator {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private volatile Settings settings;

    public HTTPProxyAuthenticator(Settings settings) {
        super();
        this.settings = settings;
    }

    @Override
    public AuthCredentials authenticate(final RestRequest request, final RestChannel channel) {

        if(request.getFromContext("_sg_xff_done") !=  Boolean.TRUE) {
            throw new ElasticsearchSecurityException("xff not done");
        }
        
        final String userHeader = settings.get("config.user_header");
        final String rolesHeader = settings.get("config.roles_header");

        log.debug("headers {}", request.headers());
        log.debug("userHeader {}, value {}", userHeader, request.header(userHeader));
        log.debug("rolesHeader {}, value {}", rolesHeader, request.header(rolesHeader));

        if (!Strings.isNullOrEmpty(userHeader) && !Strings.isNullOrEmpty((String) request.header(userHeader))) {

            String[] backendRoles = null;

            if (!Strings.isNullOrEmpty(rolesHeader) && !Strings.isNullOrEmpty((String) request.header(rolesHeader))) {
                backendRoles = ((String) request.header(rolesHeader)).split(",");
            }
            return new AuthCredentials((String) request.header(userHeader), backendRoles);
        } else {
            log.trace("No '{}' header, send 401", userHeader);
            requestAuthentication(channel);
            return null;
        }
    }

    @Override
    public void requestAuthentication(final RestChannel channel) {
        final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED);
        channel.sendResponse(wwwAuthenticateResponse);
    }

    @Override
    public String getType() {
        return "proxy";
    }
}
