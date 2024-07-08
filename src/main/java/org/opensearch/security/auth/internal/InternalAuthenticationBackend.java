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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
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

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.auth.AuthorizationBackend;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.securityconf.InternalUsersModel;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

import org.greenrobot.eventbus.Subscribe;

public class InternalAuthenticationBackend implements AuthenticationBackend, AuthorizationBackend {

    private final PasswordHasher passwordHasher;
    private InternalUsersModel internalUsersModel;

    public InternalAuthenticationBackend(PasswordHasher passwordHasher) {
        this.passwordHasher = passwordHasher;
    }

    @Override
    public boolean exists(User user) {

        if (user == null || internalUsersModel == null) {
            return false;
        }

        final boolean exists = internalUsersModel.exists(user.getName());

        if (exists) {
            user.addRoles(internalUsersModel.getBackenRoles(user.getName()));
            // FIX https://github.com/opendistro-for-elasticsearch/security/pull/23
            // Credits to @turettn
            final Map<String, String> customAttributes = internalUsersModel.getAttributes(user.getName());
            Map<String, String> attributeMap = new HashMap<>();

            if (customAttributes != null) {
                for (Entry<String, String> attributeEntry : customAttributes.entrySet()) {
                    attributeMap.put("attr.internal." + attributeEntry.getKey(), attributeEntry.getValue());
                }
            }

            final List<String> securityRoles = internalUsersModel.getSecurityRoles(user.getName());
            if (securityRoles != null) {
                user.addSecurityRoles(securityRoles);
            }

            user.addAttributes(attributeMap);
            return true;
        }

        return false;
    }

    /**
     * A helper function used to verify that both invalid and valid usernames have a hashing check during testing.
     * @param hash A string hash of the stored user's password.
     * @param array A char array of the provided password
     * @return Whether the hash matches the provided password
     */
    public boolean passwordMatchesHash(String hash, char[] array) {
        return passwordHasher.check(array, hash);
    }

    @Override
    public User authenticate(final AuthCredentials credentials) {

        boolean userExists;

        if (internalUsersModel == null) {
            throw new OpenSearchSecurityException("Internal authentication backend not configured. May be OpenSearch is not initialized.");
        }

        final byte[] password;
        String hash;
        if (!internalUsersModel.exists(credentials.getUsername())) {
            userExists = false;
            password = credentials.getPassword();
            hash = "$2y$12$NmKhjNssNgSIj8iXT7SYxeXvMA1E95a9tCt4cySY9FrQ4fB18xEc2"; // Ensure the same cryptographic complexity for users not
                                                                                   // found and invalid password
        } else {
            userExists = true;
            password = credentials.getPassword();
            hash = internalUsersModel.getHash(credentials.getUsername());
        }

        if (password == null || password.length == 0) {
            throw new OpenSearchSecurityException("empty passwords not supported");
        }

        ByteBuffer wrap = ByteBuffer.wrap(password);
        CharBuffer buf = StandardCharsets.UTF_8.decode(wrap);
        char[] array = new char[buf.limit()];
        buf.get(array);

        Arrays.fill(password, (byte) 0);

        try {
            if (passwordMatchesHash(hash, array) && userExists) {
                final List<String> roles = internalUsersModel.getBackenRoles(credentials.getUsername());
                final Map<String, String> customAttributes = internalUsersModel.getAttributes(credentials.getUsername());
                if (customAttributes != null) {
                    for (Entry<String, String> attributeName : customAttributes.entrySet()) {
                        credentials.addAttribute("attr.internal." + attributeName.getKey(), attributeName.getValue());
                    }
                }

                final User user = new User(credentials.getUsername(), roles, credentials);

                final List<String> securityRoles = internalUsersModel.getSecurityRoles(credentials.getUsername());
                if (securityRoles != null) {
                    user.addSecurityRoles(securityRoles);
                }
                return user;
            } else {
                if (!userExists) {
                    throw new OpenSearchSecurityException(credentials.getUsername() + " not found");
                }
                throw new OpenSearchSecurityException("password does not match");
            }
        } finally {
            Arrays.fill(wrap.array(), (byte) 0);
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
            throw new OpenSearchSecurityException(
                "Internal authentication backend not configured. May be OpenSearch Security is not initialized."
            );

        }

        if (exists(user)) {
            final List<String> roles = internalUsersModel.getBackenRoles(user.getName());
            if (roles != null && !roles.isEmpty() && user != null) {
                user.addRoles(roles);
            }
        }

    }

    @Subscribe
    public void onInternalUsersModelChanged(InternalUsersModel ium) {
        this.internalUsersModel = ium;
    }

}
