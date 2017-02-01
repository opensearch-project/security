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

package com.floragunn.searchguard.auth.internal;

import java.util.Arrays;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.auth.AuthenticationBackend;
import com.floragunn.searchguard.configuration.ConfigurationRepository;
import com.floragunn.searchguard.crypto.BCrypt;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;

public class InternalAuthenticationBackend implements AuthenticationBackend {

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
        
        final String[] roles = cfg.getAsArray(user.getName() + ".roles", new String[0]);
        
        if(roles != null) {
            user.addRoles(Arrays.asList(roles));
        }
        
        return true;
    }
    
    @Override
    public User authenticate(final AuthCredentials credentials) {
        
        final Settings cfg = getConfigSettings();
        if (cfg == null) {
            throw new ElasticsearchSecurityException("Internal authentication backend not configured. May be Search Guard is not initialized. See https://github.com/floragunncom/search-guard-docs/blob/master/sgadmin.md");

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
        
        byte[] password = credentials.getPassword();
        
        if(password == null || password.length == 0) {
            throw new ElasticsearchSecurityException("empty passwords not supported");
        }
        
        if (BCrypt.checkpw(password, hashed)) {
            final String[] roles = cfg.getAsArray(credentials.getUsername() + ".roles", new String[0]);
            return new User(credentials.getUsername(), Arrays.asList(roles));
        } else {
            throw new ElasticsearchSecurityException("password does not match");
        }
    }

    @Override
    public String getType() {
        return "internal";
    }

    private Settings getConfigSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_INTERNAL_USERS);
    }
}
