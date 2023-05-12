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
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.security.user.UserService;

public class ServiceAccountManagerImpl implements ServiceAccountManager {
    //TODO use it on node startup to create or get user account
    private UserService userService;

    public ServiceAccountManagerImpl(UserService userService) {
        this.userService = userService;
    }

    @Override
    public AuthToken resetServiceAccountToken(String principal) {
        //TODO
        return null;
    }

    @Override
    public Boolean isValidToken(AuthToken token) {
        //TODO
        return null;
    }

    @Override
    public void updateServiceAccount(ObjectNode contentAsNode) {
        //TODO
    }



}
