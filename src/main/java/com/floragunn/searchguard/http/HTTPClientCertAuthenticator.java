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

import org.elasticsearch.common.Strings;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

import com.floragunn.searchguard.auth.HTTPAuthenticator;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.AuthCredentials;

public class HTTPClientCertAuthenticator implements HTTPAuthenticator {

    
    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private volatile Settings settings;

    public HTTPClientCertAuthenticator(final Settings settings) {
        super();
        this.settings = settings;
    }

    @Override
    public AuthCredentials extractCredentials(final RestRequest request) {

        final String principal = request.getFromContext(ConfigConstants.SG_SSL_PRINCIPAL);

        if (!Strings.isNullOrEmpty(principal)) {
            return new AuthCredentials(principal).markComplete();
        } else {
            log.trace("No CLIENT CERT, send 401");
            return null;
        }
    }

    @Override
    public boolean reRequestAuthentication(final RestChannel channel, AuthCredentials creds) {
        return false;
    }

    @Override
    public String getType() {
        return "clientcert";
    }
}
