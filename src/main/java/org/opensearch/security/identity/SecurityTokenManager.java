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
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.identity.Subject;
import org.opensearch.identity.noop.NoopSubject;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.OnBehalfOfClaims;
import org.opensearch.identity.tokens.TokenManager;
import org.opensearch.security.action.apitokens.ApiToken;
import org.opensearch.security.authtoken.jwt.ExpiringBearerAuthToken;
import org.opensearch.security.authtoken.jwt.JwtVendor;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserService;
import org.opensearch.threadpool.ThreadPool;

import joptsimple.internal.Strings;
import org.greenrobot.eventbus.Subscribe;

/**
 * This class is the Security Plugin's implementation of the TokenManager used by all Identity Plugins.
 * It handles the issuance of both Service Account Tokens and On Behalf Of tokens.
 */
public class SecurityTokenManager implements TokenManager {
    private static final Logger logger = LogManager.getLogger(SecurityTokenManager.class);

    private final ClusterService cs;
    private final ThreadPool threadPool;
    private final UserService userService;

    private JwtVendor oboJwtVendor = null;
    private JwtVendor apiTokenJwtVendor = null;
    private ConfigModel configModel = null;

    public SecurityTokenManager(final ClusterService cs, final ThreadPool threadPool, final UserService userService) {
        this.cs = cs;
        this.threadPool = threadPool;
        this.userService = userService;
    }

    @Subscribe
    public void onConfigModelChanged(final ConfigModel configModel) {
        this.configModel = configModel;
    }

    @Subscribe
    public void onDynamicConfigModelChanged(final DynamicConfigModel dcm) {
        final Settings oboSettings = dcm.getDynamicOnBehalfOfSettings();
        final Boolean oboEnabled = oboSettings.getAsBoolean("enabled", false);
        if (oboEnabled) {
            oboJwtVendor = createJwtVendor(oboSettings);
        }
        final Settings apiTokenSettings = dcm.getDynamicApiTokenSettings();
        final Boolean apiTokenEnabled = apiTokenSettings.getAsBoolean("enabled", false);
        if (apiTokenEnabled) {
            apiTokenJwtVendor = createJwtVendor(apiTokenSettings);
        }
    }

    /** For testing */
    JwtVendor createJwtVendor(final Settings settings) {
        try {
            return new JwtVendor(settings, Optional.empty());
        } catch (final Exception ex) {
            logger.error("Unable to create the JwtVendor instance", ex);
            return null;
        }
    }

    public boolean issueOnBehalfOfTokenAllowed() {
        return oboJwtVendor != null && configModel != null;
    }

    public boolean issueApiTokenAllowed() {
        return apiTokenJwtVendor != null && configModel != null;
    }

    @Override
    public ExpiringBearerAuthToken issueOnBehalfOfToken(final Subject subject, final OnBehalfOfClaims claims) {
        if (!issueOnBehalfOfTokenAllowed()) {
            // TODO: link that doc!
            throw new OpenSearchSecurityException(
                "The OnBehalfOf token generation is not enabled, see {link to doc} for more information on this feature."
            );
        }

        if (subject != null && !(subject instanceof NoopSubject)) {
            logger.warn("Unsupported subject for OnBehalfOfToken token generation, {}", subject);
            throw new IllegalArgumentException("Unsupported subject to generate OnBehalfOfToken");
        }

        if (Strings.isNullOrEmpty(claims.getAudience())) {
            throw new IllegalArgumentException("Claims must be supplied with an audience value");
        }

        final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        if (user == null) {
            throw new OpenSearchSecurityException("Unsupported user to generate OnBehalfOfToken");
        }

        final TransportAddress callerAddress = null; /* OBO tokens must not roles based on location from network address */
        final Set<String> mappedRoles = configModel.mapSecurityRoles(user, callerAddress);

        try {
            return oboJwtVendor.createJwt(
                cs.getClusterName().value(),
                user.getName(),
                claims.getAudience(),
                claims.getExpiration(),
                new ArrayList<>(mappedRoles),
                new ArrayList<>(user.getRoles()),
                false
            );
        } catch (final Exception ex) {
            logger.error("Error creating OnBehalfOfToken for " + user.getName(), ex);
            throw new OpenSearchSecurityException("Unable to generate OnBehalfOfToken");
        }
    }

    public ExpiringBearerAuthToken issueApiToken(
        final String name,
        final Long expiration,
        final List<String> clusterPermissions,
        final List<ApiToken.IndexPermission> indexPermissions
    ) {
        final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

        try {
            return apiTokenJwtVendor.createJwt(cs.getClusterName().value(), name, name, expiration, clusterPermissions, indexPermissions);
        } catch (final Exception ex) {
            logger.error("Error creating Api Token for " + user.getName(), ex);
            throw new OpenSearchSecurityException("Unable to generate Api Token");
        }
    }

    public String encryptToken(final String token) {
        return apiTokenJwtVendor.encryptString(token);
    }

    public String decryptString(final String input) {
        return apiTokenJwtVendor.decryptString(input);
    }

    @Override
    public AuthToken issueServiceAccountToken(final String serviceId) {
        try {
            return userService.generateAuthToken(serviceId);
        } catch (final Exception e) {
            logger.error("Error creating sevice final account auth token, service " + serviceId, e);
            throw new OpenSearchSecurityException("Unable to issue service account token");
        }
    }
}
