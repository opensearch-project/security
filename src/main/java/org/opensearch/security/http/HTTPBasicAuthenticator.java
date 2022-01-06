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
 * Portions Copyright OpenSearch Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package org.opensearch.security.http;

import java.nio.file.Path;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestStatus;

import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.support.HTTPHelper;
import org.opensearch.security.user.AuthCredentials;

//TODO FUTURE allow only if protocol==https
public class HTTPBasicAuthenticator implements HTTPAuthenticator {

    protected final Logger log = LoggerFactory.getLogger(this.getClass());

    public HTTPBasicAuthenticator(final Settings settings, final Path configPath) {
    
    }

    @Override
    public AuthCredentials extractCredentials(final RestRequest request, ThreadContext threadContext) {

        final boolean forceLogin = request.paramAsBoolean("force_login", false);
        
        if(forceLogin) {
            return null;
        }
        
        final String authorizationHeader = request.header("Authorization");
        
        return HTTPHelper.extractCredentials(authorizationHeader, log);
    }

    @Override
    public boolean reRequestAuthentication(final RestChannel channel, AuthCredentials creds) {
        final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED, "Unauthorized");
        wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Basic realm=\"OpenSearch Security\"");
        channel.sendResponse(wwwAuthenticateResponse);
        return true;
    }

    @Override
    public String getType() {
        return "basic";
    }
}
