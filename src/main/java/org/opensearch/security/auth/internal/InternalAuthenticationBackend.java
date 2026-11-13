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
import java.util.Map.Entry;
import java.util.Optional;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.AuthorizationBackend;
import org.opensearch.security.auth.ImpersonationBackend;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.securityconf.InternalUsersModel;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

import org.greenrobot.eventbus.Subscribe;

public class InternalAuthenticationBackend implements AuthenticationBackend, ImpersonationBackend, AuthorizationBackend {

    private final PasswordHasher passwordHasher;
    private InternalUsersModel internalUsersModel;

    public InternalAuthenticationBackend(PasswordHasher passwordHasher) {
        this.passwordHasher = passwordHasher;
    }

    @Override
    public Optional<User> impersonate(User user) {
        if (user == null || internalUsersModel == null) {
            return Optional.empty();
        }

        final boolean exists = internalUsersModel.exists(user.getName());

        if (exists) {
            // FIX https://github.com/opendistro-for-elasticsearch/security/pull/23
            // Credits to @turettn
            ImmutableMap<String, String> customAttributes = internalUsersModel.getAttributes(user.getName());
            ImmutableMap.Builder<String, String> attributeMap = ImmutableMap.builder();

            for (Entry<String, String> attributeEntry : customAttributes.entrySet()) {
                attributeMap.put("attr.internal." + attributeEntry.getKey(), attributeEntry.getValue());
            }

            return Optional.of(
                user.withRoles(internalUsersModel.getBackendRoles(user.getName()))
                    .withSecurityRoles(internalUsersModel.getSecurityRoles(user.getName()))
                    .withAttributes(attributeMap.build())
            );
        } else {
            return Optional.empty();
        }
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
    public User authenticate(AuthenticationContext context) {
        AuthCredentials credentials = context.getCredentials();

        boolean userExists;

        if (internalUsersModel == null) {
            throw new OpenSearchSecurityException("Internal authentication backend not configured. May be OpenSearch is not initialized.");
        }

        final byte[] password;
        String hash;
        if (!internalUsersModel.exists(credentials.getUsername())) {
            userExists = false;
            password = credentials.getPassword();
            hash = passwordHasher.getDummyHash(); // Ensure the same cryptographic complexity for users not found and invalid password
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
                ImmutableSet<String> backendRoles = internalUsersModel.getBackendRoles(credentials.getUsername());
                ImmutableSet<String> securityRoles = internalUsersModel.getSecurityRoles(credentials.getUsername());
                ImmutableMap<String, String> attributeMap = ImmutableMap.<String, String>builder()
                    .putAll(credentials.getAttributes())
                    .putAll(prefixedAttributeMap(internalUsersModel.getAttributes(credentials.getUsername())))
                    .build();

                return new User(credentials.getUsername(), backendRoles, securityRoles, null, attributeMap, false);
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
    public User addRoles(User user, AuthenticationContext context) throws OpenSearchSecurityException {
        if (internalUsersModel == null) {
            throw new OpenSearchSecurityException(
                "Internal authentication backend not configured. May be OpenSearch Security is not initialized."
            );
        }

        if (internalUsersModel.exists(user.getName())) {
            return user.withRoles(internalUsersModel.getBackendRoles(user.getName()))
                .withSecurityRoles(internalUsersModel.getSecurityRoles(user.getName()))
                .withAttributes(prefixedAttributeMap(internalUsersModel.getAttributes(user.getName())));
        } else {
            return user;
        }
    }

    @Subscribe
    public void onInternalUsersModelChanged(InternalUsersModel ium) {
        this.internalUsersModel = ium;
    }

    ImmutableMap<String, String> prefixedAttributeMap(ImmutableMap<String, String> attributeMap) {
        ImmutableMap.Builder<String, String> result = ImmutableMap.builder();

        for (Entry<String, String> attributeEntry : attributeMap.entrySet()) {
            result.put("attr.internal." + attributeEntry.getKey(), attributeEntry.getValue());
        }

        return result.build();
    }

}
