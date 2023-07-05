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

package org.opensearch.security.identity;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.BasicAuthToken;
import org.opensearch.identity.tokens.BearerAuthToken;
import org.opensearch.identity.tokens.TokenManager;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.user.InternalUserTokenHandler;
import org.opensearch.security.user.UserService;
import org.opensearch.security.user.UserServiceException;
import org.opensearch.security.user.UserTokenHandler;
import org.opensearch.threadpool.ThreadPool;

/**
 * This class serves as a funneling implementation of the TokenManager interface.
 * The class allows the Security Plugin to implement two separate types of token managers without requiring specific interfaces
 * in the IdentityPlugin.
 */
public class SecurityTokenManager implements TokenManager {

    Settings settings;

    ThreadPool threadPool;

    ClusterService clusterService;
    Client client;
    ConfigurationRepository configurationRepository;
    UserService userService;
    UserTokenHandler userTokenHandler;
    InternalUserTokenHandler internalUserTokenHandler;

    public final String TOKEN_NOT_SUPPORTED_MESSAGE = "The provided token type is not supported by the Security Plugin.";

    @Inject
    public SecurityTokenManager(ThreadPool threadPool, ClusterService clusterService, ConfigurationRepository configurationRepository, Client client, Settings settings, UserService userService) {
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.client = client;
        this.configurationRepository = configurationRepository;
        this.settings = settings;
        this.userService = userService;
        userTokenHandler = new UserTokenHandler(threadPool,  clusterService,  configurationRepository,  client);
        internalUserTokenHandler = new InternalUserTokenHandler(settings, userService);

    }

    @Override
    public AuthToken issueToken() {
        throw new UserServiceException("The Security Plugin does not support generic token creation. Please specify a token type and argument.");
    }

    public AuthToken issueToken(String type, String account) throws Exception {

        AuthToken token;
        switch (type) {
            case "onBehalfOfToken":
                token = userTokenHandler.issueToken(account);
                break;
            case "internalAuthToken":
                token = internalUserTokenHandler.issueToken(account);
                break;
            default: throw new UserServiceException("The provided type " + type + " is not a valid token. Please specify either \"onBehalfOf\" or \"internalAuthToken\".");
        }
        return token;
    }

    @Override
    public boolean validateToken(AuthToken authToken) {

        if (authToken instanceof BearerAuthToken) {
            return userTokenHandler.validateToken(authToken);
        }
        if (authToken instanceof BasicAuthToken) {
            return internalUserTokenHandler.validateToken(authToken);
        }
        throw new UserServiceException(TOKEN_NOT_SUPPORTED_MESSAGE);
    }

    @Override
    public String getTokenInfo(AuthToken authToken) {

        if (authToken instanceof BearerAuthToken) {
            return userTokenHandler.getTokenInfo(authToken);
        }
        if (authToken instanceof BasicAuthToken) {
            return internalUserTokenHandler.getTokenInfo(authToken);
        }
        throw new UserServiceException(TOKEN_NOT_SUPPORTED_MESSAGE);
    }

    @Override
    public void revokeToken(AuthToken authToken) {
        if (authToken instanceof BearerAuthToken) {
            userTokenHandler.revokeToken(authToken);
            return;
        }
        if (authToken instanceof BasicAuthToken) {
            internalUserTokenHandler.revokeToken(authToken);
            return;
        }
        throw new UserServiceException(TOKEN_NOT_SUPPORTED_MESSAGE);
    }

    @Override
    public void resetToken(AuthToken authToken) {
        if (authToken instanceof BearerAuthToken) {
            userTokenHandler.resetToken(authToken);
        }
        if (authToken instanceof BasicAuthToken) {
            internalUserTokenHandler.resetToken(authToken);
        }
        throw new UserServiceException(TOKEN_NOT_SUPPORTED_MESSAGE);
    }

    /**
     * Only for testing
     */
    public void setInternalUserTokenHandler(InternalUserTokenHandler handler) {
        this.internalUserTokenHandler = handler;
    }

    /**
     * Only for testing
     */
    public void setUserTokenHandler(UserTokenHandler handler) {
        this.userTokenHandler = handler;
    }
}
