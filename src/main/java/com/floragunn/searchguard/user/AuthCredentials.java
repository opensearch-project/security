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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.elasticsearch.ElasticsearchSecurityException;

public final class AuthCredentials {

    private static final String DIGEST_ALGORITHM = "SHA-256";
    private final String username;
    private byte[] password;
    private Object nativeCredentials;
    private final Set<String> backendRoles = new HashSet<String>();
    private boolean complete;
    private final byte[] internalPasswordHash;

    public AuthCredentials(final String username, final Object nativeCredentials) {
        this(username, null, nativeCredentials);
        
        if (nativeCredentials == null) {
            throw new IllegalArgumentException("nativeCredentials must not be null or empty");
        }
    }

    public AuthCredentials(final String username, final byte[] password) {
        this(username, password, null);
        
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("password must not be null or empty");
        }
    }

    public AuthCredentials(final String username, String... backendRoles) {
        this(username, null, null, backendRoles);
    }
    
    public AuthCredentials(final AuthCredentials creds) {
        this(creds.username, creds.password, creds.nativeCredentials);
    }

    private AuthCredentials(final String username, byte[] password, Object nativeCredentials, String... backendRoles) {
        super();

        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException("username must not be null or empty");
        }

        this.username = username;
        // make defensive copy
        this.password = password == null ? null : Arrays.copyOf(password, password.length);
        
        if(this.password != null) {
            try {
                MessageDigest digester = MessageDigest.getInstance(DIGEST_ALGORITHM);
                internalPasswordHash = digester.digest(this.password);
            } catch (NoSuchAlgorithmException e) {
                throw new ElasticsearchSecurityException("Unable to digest password", e);
            }
        } else {
            internalPasswordHash = null;
        }
        
        if(password != null) {
            Arrays.fill(password, (byte) '\0');
            password = null;
        }
        
        this.nativeCredentials = nativeCredentials;
        nativeCredentials = null;
        
        if(backendRoles != null && backendRoles.length > 0) {
            this.backendRoles.addAll(Arrays.asList(backendRoles));
        }
    }

    public void clearSecrets() {
        if (password != null) {
            Arrays.fill(password, (byte) '\0');
            password = null;
        }

        nativeCredentials = null;
    }

    public String getUsername() {
        return username;
    }

    public byte[] getPassword() {
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
        result = prime * result + Arrays.hashCode(internalPasswordHash);
        result = prime * result + ((username == null) ? 0 : username.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AuthCredentials other = (AuthCredentials) obj;
        if (!Arrays.equals(internalPasswordHash, other.internalPasswordHash))
            return false;
        if (username == null) {
            if (other.username != null)
                return false;
        } else if (!username.equals(other.username))
            return false;
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

    public boolean isComplete() {
        return complete;
    }

    public AuthCredentials markComplete() {
        this.complete = true;
        return this;
    }
}
