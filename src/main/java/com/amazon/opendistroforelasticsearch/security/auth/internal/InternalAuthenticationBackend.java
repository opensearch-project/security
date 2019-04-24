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

package com.amazon.opendistroforelasticsearch.security.auth.internal;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Settings;

import com.amazon.opendistroforelasticsearch.security.auth.AuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.auth.AuthorizationBackend;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.AuthCredentials;
import com.amazon.opendistroforelasticsearch.security.user.User;

public class InternalAuthenticationBackend implements AuthenticationBackend, AuthorizationBackend {

    private final ConfigurationRepository configurationRepository;

    public InternalAuthenticationBackend(final ConfigurationRepository configurationRepository) {
        super();
        this.configurationRepository = configurationRepository;
    }

    @Override
    public boolean exists(User user) {

        final Settings cfg = getConfigSettings();
        if (cfg == null) {
            return false;
        }
        
        String hashed = cfg.get(user.getName() + ".hash");

        if (hashed == null) {
            
            for(String username:cfg.names()) {
                String u = cfg.get(username + ".username");
                if(user.getName().equals(u)) {
                    hashed = cfg.get(username+ ".hash");
                    break;
                }
            }
            
            if(hashed == null) {
                return false;
            }
        }
        
        final List<String> roles = cfg.getAsList(user.getName() + ".roles", Collections.emptyList());
        
        if(roles != null) {
            user.addRoles(roles);
        }
        
        final Settings customAttributes = cfg.getAsSettings(user.getName() + ".attributes");
        HashMap<String, String> attributeMap = new HashMap<String, String>();

        if(customAttributes != null) {
            for(String attributeName: customAttributes.names()) {
                attributeMap.put("attr.internal."+attributeName, customAttributes.get(attributeName));
            }
        }

        user.addAttributes(attributeMap);

        return true;
    }
    
    @Override
    public User authenticate(final AuthCredentials credentials) {
        
        final Settings cfg = getConfigSettings();
        if (cfg == null) {
            throw new ElasticsearchSecurityException("Internal authentication backend not configured. May be Open Distro Security is not initialized");

        }

        String hashed = cfg.get(credentials.getUsername() + ".hash");

        if (hashed == null) {
            
            for(String username:cfg.names()) {
                String u = cfg.get(username + ".username");
                if(credentials.getUsername().equals(u)) {
                    hashed = cfg.get(username+ ".hash");
                    break;
                }
            }
            
            if(hashed == null) {
                throw new ElasticsearchSecurityException(credentials.getUsername() + " not found");
            }
        }
        
        final byte[] password = credentials.getPassword();
        
        if(password == null || password.length == 0) {
            throw new ElasticsearchSecurityException("empty passwords not supported");
        }

        ByteBuffer wrap = ByteBuffer.wrap(password);
        CharBuffer buf = StandardCharsets.UTF_8.decode(wrap);
        char[] array = new char[buf.limit()];
        buf.get(array);
        
        Arrays.fill(password, (byte)0);
       
        try {
            if (OpenBSDBCrypt.checkPassword(hashed, array)) {
                final List<String> roles = cfg.getAsList(credentials.getUsername() + ".roles", Collections.emptyList());
                final Settings customAttributes = cfg.getAsSettings(credentials.getUsername() + ".attributes");

                if(customAttributes != null) {
                    for(String attributeName: customAttributes.names()) {
                        credentials.addAttribute("attr.internal."+attributeName, customAttributes.get(attributeName));
                    }
                }

                return new User(credentials.getUsername(), roles, credentials);
            } else {
                throw new ElasticsearchSecurityException("password does not match");
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

    private Settings getConfigSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_INTERNAL_USERS);
    }

    @Override
    public void fillRoles(User user, AuthCredentials credentials) throws ElasticsearchSecurityException {
        final Settings cfg = getConfigSettings();
        if (cfg == null) {
            throw new ElasticsearchSecurityException("Internal authentication backend not configured. May be Open Distro Security is not initialized.");

        }
        final List<String> roles = cfg.getAsList(credentials.getUsername() + ".roles", Collections.emptyList());
        if(roles != null && !roles.isEmpty() && user != null) {
            user.addRoles(roles);
        }
    }
}
