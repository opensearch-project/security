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

package com.floragunn.searchguard.auth;

import org.elasticsearch.ElasticsearchSecurityException;

import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;

public interface AuthenticationBackend {

    String getType();

    /**
     * 
     * @param credentials
     *            , must not be null
     * @return the authenticated User, never null
     * @throws ElasticsearchSecurityException
     */
    User authenticate(AuthCredentials credentials) throws ElasticsearchSecurityException;

}
