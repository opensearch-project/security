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

package org.opensearch.security.user;

import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.BasicAuthToken;
import org.opensearch.identity.tokens.TokenManager;
import org.opensearch.security.securityconf.Hashed;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static org.opensearch.security.dlic.rest.support.Utils.universalHash;

public class InternalUserTokenHandler implements TokenManager {

    Settings settings;

    UserService userService;

    public SecurityDynamicConfiguration<?> internalUsersConfiguration;


    @Inject
    public InternalUserTokenHandler(final Settings settings, UserService userService) {
        this.settings = settings;
        this.userService = userService;
        this.internalUsersConfiguration = userService.geInternalUsersConfigurationRepository();
    }

    public AuthToken issueToken() {
        throw new UserServiceException("The InternalUserTokenHandler is unable to issue generic auth tokens. Please specify a valid internal user.");
    }

    public AuthToken issueToken(String internalUser) {
        String tokenAsString;
        try {
            tokenAsString = this.userService.generateAuthToken(internalUser);
        } catch (IOException | UserServiceException ex){
            throw new UserServiceException("Failed to generate an auth token for " + internalUser);
        }
        return new BasicAuthToken(tokenAsString);
    }

    public boolean validateToken(AuthToken token) {
        if (!(token instanceof BasicAuthToken)) {
            throw new UserServiceException("The provided auth token is of an incorrect type. Please provide a BasicAuthToken object.");
        }
        BasicAuthToken basicToken  = (BasicAuthToken) token;
        String accountName = basicToken.getUser();
        String password = basicToken.getPassword();
        String hash;
        try {
            hash = universalHash(password);
        } catch (NoSuchAlgorithmException e) {
            throw new UserServiceException("The provided token could not be validated.");
        }
        return (internalUsersConfiguration.exists(accountName) && hash.equals(((Hashed) internalUsersConfiguration.getCEntry(accountName)).getHash()));
    }

    public String getTokenInfo(AuthToken token) {
        if (!(token instanceof BasicAuthToken)) {
            throw new UserServiceException("The provided token is not a BasicAuthToken.");
        }
        BasicAuthToken basicAuthToken = (BasicAuthToken) token;
        return "The provided token is a BasicAuthToken with content: " + basicAuthToken;
    }

    public void revokeToken(AuthToken token) {
        if (validateToken(token)) {
            BasicAuthToken basicToken  = (BasicAuthToken) token;
            String accountName = basicToken.getUser();
            try {
                userService.clearHash(accountName);
                return;
            } catch (IOException e) {
                throw new UserServiceException(e.getMessage());
            }
        }
        throw new UserServiceException("The token could not be revoked.");
    }

    public void resetToken(AuthToken token) {
        throw new UserServiceException("The InternalUserTokenHandler is unable to reset auth tokens.");
    }
}

