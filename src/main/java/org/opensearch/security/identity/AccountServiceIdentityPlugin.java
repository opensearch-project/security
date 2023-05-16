/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.identity;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.opensearch.identity.ServiceAccountManager;
import org.opensearch.identity.Subject;
import org.opensearch.identity.User;
import org.opensearch.identity.UserProvider;
import org.opensearch.plugins.IdentityPlugin;
import org.opensearch.security.user.UserService;

import java.io.IOException;
import java.util.List;

public class AccountServiceIdentityPlugin implements IdentityPlugin {
    private UserService userService;

    public AccountServiceIdentityPlugin(UserService userService) {
        this.userService = userService;
    }

    @Override
    public Subject getSubject() {
        //TODO
        return null;
    }

    @Override
    public ServiceAccountManager getServiceAccountManager() {
        return new ServiceAccountManagerImpl(this.userService);
    }

    @Override
    public UserProvider getUserProvider() {
        return new UserProvider() {
            @Override
            public User getUser(String username) {
                return userService.getUser(username);
            }

            @Override
            public void removeUser(String username) {
                userService.removeUserByName(username);
            }

            @Override
            public void putUser(ObjectNode userContent) {
                try {
                    userService.createOrUpdateAccount(userContent);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public List<User> getUsers() {
                return userService.getUsers();
            }
        };
    }
}
