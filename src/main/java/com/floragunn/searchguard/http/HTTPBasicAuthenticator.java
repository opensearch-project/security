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

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.floragunn.searchguard.auth.HTTPAuthenticator;
import com.floragunn.searchguard.support.HTTPHelper;
import com.floragunn.searchguard.user.AuthCredentials;

//TODO FUTURE allow only if protocol==https
public class HTTPBasicAuthenticator implements HTTPAuthenticator {

    protected final ESLogger log = Loggers.getLogger(this.getClass());

    public HTTPBasicAuthenticator(final Settings settings) {
    
    }

    @Override
    public AuthCredentials extractCredentials(final RestRequest request) {

        final boolean forceLogin = request.paramAsBoolean("force_login", false);
        
        if(forceLogin) {
            return null;
        }
        
        final String authorizationHeader = request.header("Authorization");
        
        return HTTPHelper.extractCredentials(authorizationHeader, log);
    }

    @Override
    public boolean reRequestAuthentication(final RestChannel channel, AuthCredentials creds) {
        final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED);
        wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Basic realm=\"Search Guard\"");
        channel.sendResponse(wwwAuthenticateResponse);
        return true;
    }

    @Override
    public String getType() {
        return "basic";
    }
}
