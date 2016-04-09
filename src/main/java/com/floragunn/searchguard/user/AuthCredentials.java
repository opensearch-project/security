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

package com.floragunn.searchguard.user;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.elasticsearch.common.Strings;

public final class AuthCredentials {

    private final String username;
    private char[] password;
    private Object nativeCredentials;
    private Set<String> backendRoles = new HashSet<String>();

    public AuthCredentials(final String username, final Object nativeCredentials) {
        this(username, null, nativeCredentials);
    }

    public AuthCredentials(final String username, final char[] password) {
        this(username, password, null);
    }

    public AuthCredentials(final String username, String... backendRoles) {
        this(username, null, null, backendRoles);
    }
    
    public AuthCredentials(final AuthCredentials creds) {
        this(creds.username, creds.password, creds.nativeCredentials);
    }

    private AuthCredentials(final String username, char[] password, Object nativeCredentials, String... backendRoles) {
        super();

        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException("username must not be null or empty");
        }

        this.username = username;
        // make defensive copy
        this.password = password == null ? null : Arrays.copyOf(password, password.length);
        password = null;
        this.nativeCredentials = nativeCredentials;
        nativeCredentials = null;
        
        if(backendRoles != null && backendRoles.length > 0) {
            this.backendRoles.addAll(Arrays.asList(backendRoles));
        }
    }

    public void clear() {
        if (password != null) {
            Arrays.fill(password, '\0');
            password = null;
        }

        nativeCredentials = null;
        backendRoles.clear();
    }

    public String getUsername() {
        return username;
    }

    public char[] getPassword() {
        // make defensive copy
        return password == null ? null : Arrays.copyOf(password, password.length);
    }

    public Object getNativeCredentials() {
        return nativeCredentials;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (nativeCredentials == null ? 0 : nativeCredentials.hashCode());
        result = prime * result + Arrays.hashCode(password);
        result = prime * result + (username == null ? 0 : username.hashCode());
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AuthCredentials other = (AuthCredentials) obj;
        if (nativeCredentials == null) {
            if (other.nativeCredentials != null) {
                return false;
            }
        } else if (!nativeCredentials.equals(other.nativeCredentials)) {
            return false;
        }
        if (!Arrays.equals(password, other.password)) {
            return false;
        }
        if (username == null) {
            if (other.username != null) {
                return false;
            }
        } else if (!username.equals(other.username)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "AuthCredentials [username=" + username + ", password empty=" + (password == null) + ", nativeCredentials empty="
                + (nativeCredentials == null) + ",backendRoles="+backendRoles+"]";
    }

    public Set<String> getBackendRoles() {
        return new HashSet<String>(backendRoles);
    }

    
}
