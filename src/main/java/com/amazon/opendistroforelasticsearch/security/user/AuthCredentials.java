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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.jayway.jsonpath.JsonPath;
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
    private final Map<String, Object> structuredAttributes;
    private Map<String, Object> claims = new HashMap<>();

    /**
     * Create new credentials with a username and native credentials
     *
     * @param username The username, must not be null or empty
     * @param nativeCredentials Arbitrary credentials (like GSS tokens), must not be null
     * @throws IllegalArgumentException if username or nativeCredentials are null or empty
     */
    public AuthCredentials(final String username, final Object nativeCredentials) {
        this(username, null, nativeCredentials, null, null);

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
        this(username, password, null, null, null);

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
        this(username, null, null, null, null, backendRoles);
    }

    private AuthCredentials(final String username, byte[] password, Object nativeCredentials, Map<String, Object> structuredAttributes, Map<String, Object> claims,
                            String... backendRoles) {
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
        this.structuredAttributes = structuredAttributes;

        if (claims != null) {
            this.claims = Collections.unmodifiableMap(claims);
        } else {
            this.claims = new HashMap<>();
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

    public Map<String, Object> getStructuredAttributes() {
        return structuredAttributes;
    }

    public Map<String, Object> getClaims() {
        return claims;
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
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AuthCredentials other = (AuthCredentials) obj;
        if (internalPasswordHash == null || other.internalPasswordHash == null || !MessageDigest.isEqual(internalPasswordHash, other.internalPasswordHash))
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

    public static class Builder {
        private static final String DIGEST_ALGORITHM = "SHA-256";
        private String username;
        private byte[] password;
        private Object nativeCredentials;
        private Set<String> backendRoles = new HashSet<String>();
        private boolean complete;
        private byte[] internalPasswordHash;
        private Map<String, String> attributes = new HashMap<>();
        private Map<String, Object> structuredAttributes;
        private Map<String, Object> claims = new HashMap<>();

        public Builder() {

        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder password(byte[] password) {
            if (password == null || password.length == 0) {
                throw new IllegalArgumentException("password must not be null or empty");
            }

            this.password = Arrays.copyOf(password, password.length);

            try {
                MessageDigest digester = MessageDigest.getInstance(DIGEST_ALGORITHM);
                internalPasswordHash = digester.digest(this.password);
            } catch (NoSuchAlgorithmException e) {
                throw new ElasticsearchSecurityException("Unable to digest password", e);
            }

            Arrays.fill(password, (byte) '\0');

            return this;
        }

        public Builder password(String password) {
            return this.password(password.getBytes(StandardCharsets.UTF_8));
        }

        public Builder nativeCredentials(Object nativeCredentials) {
            if (nativeCredentials == null) {
                throw new IllegalArgumentException("nativeCredentials must not be null or empty");
            }
            this.nativeCredentials = nativeCredentials;
            return this;
        }

        public Builder backendRoles(String... backendRoles) {
            if (backendRoles == null) {
                return this;
            }

            this.backendRoles.addAll(Arrays.asList(backendRoles));
            return this;
        }

        /**
         * If the credentials are complete and no further roundtrips with the originator are due
         * then this method <b>must</b> be called so that the authentication flow can proceed.
         * <p/>
         * If this credentials are already marked a complete then a call to this method does nothing.
         */
        public Builder complete() {
            this.complete = true;
            return this;
        }

        public Builder oldAttribute(String name, String value) {
            if (name != null && !name.isEmpty()) {
                this.attributes.put(name, value);
            }
            return this;
        }

        public Builder oldAttributes(Map<String, String> map) {
            this.attributes.putAll(map);
            return this;
        }

        public Builder prefixOldAttributes(String keyPrefix, Map<String, ?> map) {
            for (Map.Entry<String, ?> entry : map.entrySet()) {
                this.attributes.put(keyPrefix + entry.getKey(), entry.getValue() != null ? entry.getValue().toString() : null);
            }
            return this;
        }

        public Builder attribute(String name, Object value) {
            UserAttributes.validate(value);

            if (name != null && !name.isEmpty()) {
                this.structuredAttributes.put(name, value);
            }
            return this;
        }

        public Builder attributes(Map<String, Object> map) {
            UserAttributes.validate(map);
            this.structuredAttributes.putAll(map);
            return this;
        }

        public Builder attributesByJsonPath(Map<String, JsonPath> jsonPathMap, Object source) {
            UserAttributes.addAttributesByJsonPath(jsonPathMap, source, this.structuredAttributes);
            return this;
        }

        public Builder claims(Map<String, Object> map) {
            this.claims.putAll(map);
            return this;
        }


        public String getUsername() {
            return username;
        }

        public Map<String, Object> getStructuredAttributes() {
            return structuredAttributes;
        }

        public AuthCredentials build() {
            int n = backendRoles.size();
            String roles[] = new String[n];
            System.arraycopy(backendRoles.toArray(), 0, roles, 0, n);

            AuthCredentials result = new AuthCredentials(username, password, nativeCredentials, structuredAttributes, claims,
                    roles);
            this.password = null;
            this.nativeCredentials = null;
            this.internalPasswordHash = null;
            return result;
        }
    }


    public static Builder forUser(String username) {
        return new Builder().username(username);
    }


}
