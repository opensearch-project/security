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

package com.amazon.opendistroforelasticsearch.security.user;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.elasticsearch.ElasticsearchSecurityException;

/**
 * AuthCredentials are an abstraction to encapsulate credentials like passwords or generic
 * native credentials like GSS tokens.
 *
 */
public final class AuthCredentials {

    private static final String DIGEST_ALGORITHM = "SHA-256";
    private final String username;
    private byte[] password;
    private Object nativeCredentials;
    private final Set<String> backendRoles = new HashSet<String>();
    private boolean complete;
    private final byte[] internalPasswordHash;
    private final Map<String, String> attributes = new HashMap<>();

    /**
     * Create new credentials with a username and native credentials
     *
     * @param username The username, must not be null or empty
     * @param nativeCredentials Arbitrary credentials (like GSS tokens), must not be null
     * @throws IllegalArgumentException if username or nativeCredentials are null or empty
     */
    public AuthCredentials(final String username, final Object nativeCredentials) {
        this(username, null, nativeCredentials);

        if (nativeCredentials == null) {
            throw new IllegalArgumentException("nativeCredentials must not be null or empty");
        }
    }

    /**
     * Create new credentials with a username and password
     *
     * @param username The username, must not be null or empty
     * @param password The password, must not be null or empty
     * @throws IllegalArgumentException if username or password is null or empty
     */
    public AuthCredentials(final String username, final byte[] password) {
        this(username, password, null);

        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("password must not be null or empty");
        }
    }

    /**
     * Create new credentials with a username, a initial optional set of roles and empty password/native credentials

     * @param username The username, must not be null or empty
     * @param backendRoles set of roles this user is a member of
     * @throws IllegalArgumentException if username is null or empty
     */
    public AuthCredentials(final String username, String... backendRoles) {
        this(username, null, null, backendRoles);
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

    /**
     * Wipe password and native credentials
     */
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

    /**
     *
     * @return Defensive copy of the password
     */
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
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }

        AuthCredentials other = (AuthCredentials) obj;
        return Objects.equals(username, other.username)
            && Arrays.equals(password, other.password)
            && Objects.equals(nativeCredentials, other.nativeCredentials)
            && Objects.equals(backendRoles, other.backendRoles)
            && MessageDigest.isEqual(internalPasswordHash, other.internalPasswordHash)
            && Objects.equals(attributes, other.attributes);
    }

    @Override
    public String toString() {
        return "AuthCredentials [username=" + username + ", password empty=" + (password == null) + ", nativeCredentials empty="
                + (nativeCredentials == null) + ",backendRoles="+backendRoles+"]";
    }

    /**
     *
     * @return Defensive copy of the roles this user is member of.
     */
    public Set<String> getBackendRoles() {
        return new HashSet<String>(backendRoles);
    }

    public boolean isComplete() {
        return complete;
    }

    /**
     * If the credentials are complete and no further roundtrips with the originator are due
     * then this method <b>must</b> be called so that the authentication flow can proceed.
     * <p/>
     * If this credentials are already marked a complete then a call to this method does nothing.
     *
     * @return this
     */
    public AuthCredentials markComplete() {
        this.complete = true;
        return this;
    }

    public void addAttribute(String name, String value) {
        if(name != null && !name.isEmpty()) {
            this.attributes.put(name, value);
        }
    }

    public Map<String, String> getAttributes() {
        return Collections.unmodifiableMap(this.attributes);
    }
}
