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

import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import com.amazon.opendistroforelasticsearch.security.user.User;

/**
 * Open Distro Security custom authentication backends need to implement this interface.
 * <p/>
 * Authentication backends verify {@link AuthCredentials} and, if successfully verified, return a {@link User}.
 * <p/>
 * Implementation classes must provide a public constructor
 * <p/>
 * {@code public MyHTTPAuthenticator(org.elasticsearch.common.settings.Settings settings, java.nio.file.Path configPath)}
 * <p/>
 * The constructor should not throw any exception in case of an initialization problem.
 * Instead catch all exceptions and log a appropriate error message. A logger can be instantiated like:
 * <p/>
 * {@code private final Logger log = LogManager.getLogger(this.getClass());}
 * 
 * <p/>
 */
public interface AuthenticationBackend {

    /**
     * The type (name) of the authenticator. Only for logging.  
     * @return the type
     */
    String getType();

    /**
     * Validate credentials and return an authenticated user (or throw an ElasticsearchSecurityException)
     * <p/>
     * Results of this method are normally cached so that we not need to query the backend for every authentication attempt.
     * <p/> 
     * @param The credentials to be validated, never null
     * @return the authenticated User, never null
     * @throws ElasticsearchSecurityException in case an authentication failure 
     * (when credentials are incorrect, the user does not exist or the backend is not reachable)
     */
    User authenticate(AuthCredentials credentials) throws ElasticsearchSecurityException;
    
    /**
     * 
     * Lookup for a specific user in the authentication backend
     * 
     * @param user The user for which the authentication backend should be queried
     * @return true if the user exists in the authentication backend, false otherwise
     */
    boolean exists(User user);

}
