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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistroforelasticsearch.security.auth;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;

/**
 * Open Distro Security custom HTTP authenticators need to implement this interface.
 * <p/>
 * A HTTP authenticator extracts {@link AuthCredentials} from a {@link RestRequest}
 * <p/>
 * 
 * Implementation classes must provide a public constructor
 * <p/>
 * {@code public MyHTTPAuthenticator(org.elasticsearch.common.settings.Settings settings, java.nio.file.Path configPath)}
 * <p/>
 * The constructor should not throw any exception in case of an initialization problem.
 * Instead catch all exceptions and log a appropriate error message. A logger can be instantiated like:
 * <p/>
 * {@code private final Logger log = LogManager.getLogger(this.getClass());}
 * <p/>
 */
public interface HTTPAuthenticator {

    /**
     * The type (name) of the authenticator. Only for logging.  
     * @return the type
     */
    String getType();
    
    /**
     * Extract {@link AuthCredentials} from {@link RestRequest}
     * 
     * @param request The rest request
     * @param context The current thread context
     * @return The authentication credentials (complete or incomplete) or null when no credentials are found in the request
     * <p>
     * When the credentials could be fully extracted from the request {@code .markComplete()} must be called on the {@link AuthCredentials} which are returned.
     * If the authentication flow needs another roundtrip with the request originator do not mark it as complete.
     * @throws ElasticsearchSecurityException
     */
    AuthCredentials extractCredentials(RestRequest request, ThreadContext context) throws ElasticsearchSecurityException;
    
    /**
     * If the {@code extractCredentials()} call was not successful or the authentication flow needs another roundtrip this method
     * will be called. If the custom HTTP authenticator does not support this method is a no-op and false should be returned.
     * 
     * If the custom HTTP authenticator does support re-request authentication or supports authentication flows with multiple roundtrips
     * then the response should be sent (through the channel) and true must be returned.
     * 
     * @param channel The rest channel to sent back the response via {@code channel.sendResponse()}
     * @param credentials The credentials from the prior authentication attempt
     * @return false  if re-request is not supported/necessary, true otherwise. 
     * If true is returned {@code channel.sendResponse()} must be called so that the request completes.
     */
    boolean reRequestAuthentication(final RestChannel channel, AuthCredentials credentials);
}
