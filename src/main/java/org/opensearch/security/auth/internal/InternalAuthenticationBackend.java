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

package org.opensearch.security.auth.internal;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.opensearch.OpenSearchSecurityException;

import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.auth.AuthorizationBackend;
import org.opensearch.security.securityconf.InternalUsersModel;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;
import org.greenrobot.eventbus.Subscribe;

public class InternalAuthenticationBackend implements AuthenticationBackend, AuthorizationBackend {

    private InternalUsersModel internalUsersModel;

    @Override
    public boolean exists(User user) {

        if(user == null || internalUsersModel == null) {
            return false;
        }

        final boolean exists = internalUsersModel.exists(user.getName());

        if(exists) {
            user.addRoles(internalUsersModel.getBackenRoles(user.getName()));
            //FIX https://github.com/opendistro-for-elasticsearch/security/pull/23
            //Credits to @turettn
            final Map<String, String> customAttributes = internalUsersModel.getAttributes(user.getName());
            Map<String, String> attributeMap = new HashMap<>();

            if(customAttributes != null) {
                for(Entry<String, String> attributeEntry: customAttributes.entrySet()) {
                    attributeMap.put("attr.internal."+attributeEntry.getKey(), attributeEntry.getValue());
                }
            }

            final List<String> securityRoles = internalUsersModel.getSecurityRoles(user.getName());
            if(securityRoles != null) {
                user.addSecurityRoles(securityRoles);
            }
            
            user.addAttributes(attributeMap);
            return true;
        }

        return false;
    }

    @Override
    public User authenticate(final AuthCredentials credentials) {

        if (internalUsersModel == null) {
            throw new OpenSearchSecurityException("Internal authentication backend not configured. May be OpenSearch is not initialized.");
        }

        if(!internalUsersModel.exists(credentials.getUsername())) {
            throw new OpenSearchSecurityException(credentials.getUsername() + " not found");
        }

        final byte[] password = credentials.getPassword();

        if(password == null || password.length == 0) {
            throw new OpenSearchSecurityException("empty passwords not supported");
        }

        ByteBuffer wrap = ByteBuffer.wrap(password);
        CharBuffer buf = StandardCharsets.UTF_8.decode(wrap);
        char[] array = new char[buf.limit()];
        buf.get(array);

        Arrays.fill(password, (byte)0);

        try {
            if (OpenBSDBCrypt.checkPassword(internalUsersModel.getHash(credentials.getUsername()), array)) {
                final List<String> roles = internalUsersModel.getBackenRoles(credentials.getUsername());
                final Map<String, String> customAttributes = internalUsersModel.getAttributes(credentials.getUsername());
                if(customAttributes != null) {
                    for(Entry<String, String> attributeName: customAttributes.entrySet()) {
                        credentials.addAttribute("attr.internal."+attributeName.getKey(), attributeName.getValue());
                    }
                }
                
                final User user = new User(credentials.getUsername(), roles, credentials);
                
                final List<String> securityRoles = internalUsersModel.getSecurityRoles(credentials.getUsername());
                if(securityRoles != null) {
                    user.addSecurityRoles(securityRoles);
                }
                
                return user;
            } else {
                throw new OpenSearchSecurityException("password does not match");
            }
        } finally {
            Arrays.fill(wrap.array(), (byte)0);
            Arrays.fill(buf.array(), '\0');
            Arrays.fill(array, '\0');
        }
    }

    @Override
    public String getType() {
        return "internal";
    }

    @Override
    public void fillRoles(User user, AuthCredentials credentials) throws OpenSearchSecurityException {

        if (internalUsersModel == null) {
            throw new OpenSearchSecurityException("Internal authentication backend not configured. May be OpenSearch Security is not initialized.");

        }

        if(exists(user)) {
            final List<String> roles = internalUsersModel.getBackenRoles(user.getName());
            if(roles != null && !roles.isEmpty() && user != null) {
                user.addRoles(roles);
            }
        }


    }

    @Subscribe
    public void onInternalUsersModelChanged(InternalUsersModel ium) {
        this.internalUsersModel = ium;
    }


}