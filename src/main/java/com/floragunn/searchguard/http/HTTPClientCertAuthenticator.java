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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

import com.floragunn.searchguard.auth.HTTPAuthenticator;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.AuthCredentials;

public class HTTPClientCertAuthenticator implements HTTPAuthenticator {
    
    protected final Logger log = LogManager.getLogger(this.getClass());
    private volatile Settings settings;

    public HTTPClientCertAuthenticator(final Settings settings) {
        this.settings = settings;
    }

    @Override
    public AuthCredentials extractCredentials(final RestRequest request, ThreadContext threadContext) {

        String principal = threadContext.getTransient(ConfigConstants.SG_SSL_PRINCIPAL);

        if (!Strings.isNullOrEmpty(principal)) {
            
            final String usernameAttribute = settings.get("username_attribute");
            
            if(principal != null && usernameAttribute != null && usernameAttribute.length() > 0) {
                final int start = principal.toLowerCase().indexOf(usernameAttribute.toLowerCase()+"=");
                
                if(start > -1) {
                    final int commaIndex = principal.indexOf(",", start);
                    principal = principal.substring(start+3, commaIndex==-1?principal.length():commaIndex);
                }
            }
            
            
            return new AuthCredentials(principal.trim()).markComplete();
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
