/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.identity;

import org.opensearch.identity.ServiceAccountManager;
import org.opensearch.identity.Subject;
import org.opensearch.identity.UserProvider;
import org.opensearch.plugins.IdentityPlugin;
import org.opensearch.security.user.UserService;

public class AccountServiceIdentityPlugin implements IdentityPlugin {
    //TODO
    public static String name = "AccountServiceIdentityPlugin";
    private UserService userService;

    public AccountServiceIdentityPlugin(UserService userService) {
        this.userService = userService;
    }

    @Override
    public Subject getSubject() {
        return null;
    }

    @Override
    public ServiceAccountManager getServiceAccountManager() {
        return new ServiceAccountManagerImpl(this.userService);
    }

    @Override
    public UserProvider getUserProvider() {
        return null;
    }
}
