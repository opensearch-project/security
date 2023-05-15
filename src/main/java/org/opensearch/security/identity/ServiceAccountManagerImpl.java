/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.identity;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.identity.ServiceAccountManager;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.BasicAuthToken;
import org.opensearch.security.user.UserService;

import java.io.IOException;

public class ServiceAccountManagerImpl implements ServiceAccountManager {

    private static final Logger log = LogManager.getLogger(ServiceAccountManagerImpl.class);
    private UserService userService;

    public ServiceAccountManagerImpl(UserService userService) {
        this.userService = userService;
    }

    @Override
    public AuthToken resetServiceAccountToken(String username) {
        try {
            String token = userService.generateAuthToken(username);
            return new Token(username, token);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Boolean isValidToken(AuthToken token) {

        if (token instanceof BasicAuthToken) {
            return userService.userExists(((BasicAuthToken) token).getUser());
        }
        if (token instanceof Token) {
            return userService.userExists(((Token) token).getUsername());
        }
        return false;
    }

    @Override
    public void updateServiceAccount(ObjectNode contentAsNode) {
        try {
            userService.createOrUpdateAccount(contentAsNode);
        } catch (IOException e) {
            log.error("Error while trying to create or update account", e);
        }
    }

    @Override
    public boolean getOrCreateServiceAccount(ObjectNode objectNode) throws IOException {
        //Do we want to return service account or boolean confirming account was created?
        try {
            userService.createOrUpdateAccount(objectNode);
            log.info("Service account exists");
            return true;
        } catch (IOException e) {
            log.warn("Error while trying to create service account", e);
        }
        return false;
    }
    //TODO move to core
    private class Token implements AuthToken {
        private String username;
        private String password;

        public Token(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }
    }
}
