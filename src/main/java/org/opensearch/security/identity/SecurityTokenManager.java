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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.apache.cxf.rs.security.jose.jwt.JwtConstants;
import org.greenrobot.eventbus.Subscribe;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.BasicAuthToken;
import org.opensearch.identity.tokens.BearerAuthToken;
import org.opensearch.identity.tokens.TokenManager;
import org.opensearch.security.authtoken.jwt.JwtVendor;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.InternalUserTokenHandler;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserService;
import org.opensearch.security.user.UserServiceException;
import org.opensearch.security.user.UserTokenHandler;
import org.opensearch.threadpool.ThreadPool;
import org.apache.cxf.rs.security.jose.jwt.JwtConstants;

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
    private ConfigModel configModel;
    private DynamicConfigModel dcm;
    private JwtVendor vendor;

    @Inject
    public SecurityTokenManager(
        ThreadPool threadPool,
        ClusterService clusterService,
        ConfigurationRepository configurationRepository,
        Client client,
        Settings settings,
        UserService userService
    ) {
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.client = client;
        this.configurationRepository = configurationRepository;
        this.settings = settings;
        this.userService = userService;
        userTokenHandler = new UserTokenHandler(threadPool, clusterService, configurationRepository, client);
        internalUserTokenHandler = new InternalUserTokenHandler(settings, userService);

    }

    @Override
    public AuthToken issueToken(String account) {

        AuthToken token;
        final SecurityDynamicConfiguration<?> internalUsersConfiguration = load(UserService.getUserConfigName(), false);
        if (internalUsersConfiguration.exists(account)) {
            token = internalUserTokenHandler.issueToken(account);
        } else {
            token = userTokenHandler.issueToken(account);
        }
        return token;
    }

    @Override
    public AuthToken issueOnBehalfOfToken(Map<String, Object> claims) {
        String oboToken;

        User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        if (user == null && !claims.containsKey(JwtConstants.CLAIM_AUDIENCE)) {
            throw new OpenSearchSecurityException("On-behalf-of Token cannot be issued due to the missing of subject/audience.");
        }

        final TransportAddress caller = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);

        String issuer = clusterService.getClusterName().value();
        String subject = user.getName();
        String audience = (String) claims.get(JwtConstants.CLAIM_AUDIENCE);
        Integer expirySeconds = null;
        List<String> roles = new ArrayList<>(mapRoles(user, caller));
        List<String> backendRoles = new ArrayList<>(user.getRoles());

        try {
            oboToken = vendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return new BearerAuthToken(oboToken);
    }

    @Override
    public AuthToken issueServiceAccountToken(String pluginOrExtensionPrincipal) {
        return null;
    }

    public boolean validateToken(AuthToken authToken) {

        if (authToken instanceof BearerAuthToken) {
            return userTokenHandler.validateToken(authToken);
        }
        if (authToken instanceof BasicAuthToken) {
            return internalUserTokenHandler.validateToken(authToken);
        }
        throw new UserServiceException(TOKEN_NOT_SUPPORTED_MESSAGE);
    }

    public String getTokenInfo(AuthToken authToken) {

        if (authToken instanceof BearerAuthToken) {
            return userTokenHandler.getTokenInfo(authToken);
        }
        if (authToken instanceof BasicAuthToken) {
            return internalUserTokenHandler.getTokenInfo(authToken);
        }
        throw new UserServiceException(TOKEN_NOT_SUPPORTED_MESSAGE);
    }

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

    /**
     * Load data for a given CType
     * @param config CType whose data is to be loaded in-memory
     * @return configuration loaded with given CType data
     */
    protected final SecurityDynamicConfiguration<?> load(final CType config, boolean logComplianceEvent) {
        SecurityDynamicConfiguration<?> loaded = configurationRepository.getConfigurationsFromIndex(
            Collections.singleton(config),
            logComplianceEvent
        ).get(config).deepClone();
        return DynamicConfigFactory.addStatics(loaded);
    }

    public Set<String> mapRoles(final User user, final TransportAddress caller) {
        return this.configModel.mapSecurityRoles(user, caller);
    }

    @Subscribe
    public void onConfigModelChanged(ConfigModel configModel) {
        this.configModel = configModel;
    }

    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
        this.dcm = dcm;
        if (dcm.getDynamicOnBehalfOfSettings().get("signing_key") != null
            && dcm.getDynamicOnBehalfOfSettings().get("encryption_key") != null) {
            this.vendor = new JwtVendor(dcm.getDynamicOnBehalfOfSettings(), Optional.empty());
        } else {
            this.vendor = null;
        }
    }
}
