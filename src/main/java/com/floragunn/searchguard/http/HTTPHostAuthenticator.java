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
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

import com.floragunn.searchguard.auth.HTTPAuthenticator;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.AuthCredentials;

@Deprecated
public class HTTPHostAuthenticator implements HTTPAuthenticator {

    public HTTPHostAuthenticator(Settings settings) {
        super();
    }

    @Override
    public AuthCredentials extractCredentials(final RestRequest request, ThreadContext threadContext) {
        
        TransportAddress hostAddress = threadContext.getTransient(ConfigConstants.SG_REMOTE_ADDRESS);
        
        if(hostAddress == null || !(hostAddress instanceof InetSocketTransportAddress)) {
            throw new ElasticsearchSecurityException("No valid host address found");
        }
        
        return new AuthCredentials("sg_host_"+((InetSocketTransportAddress) hostAddress).address().getHostString()).markComplete();
    }

    @Override
    public boolean reRequestAuthentication(final RestChannel channel, AuthCredentials creds) {
        return false;
    }

    @Override
    public String getType() {
        return "host";
    }
}
