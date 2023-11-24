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

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

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

    private JwtVendor jwtVendor = null;
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
        final Boolean enabled = oboSettings.getAsBoolean("enabled", false);
        if (enabled) {
            jwtVendor = createJwtVendor(oboSettings);
        } else {
            jwtVendor = null;
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
        return jwtVendor != null && configModel != null;
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
            return jwtVendor.createJwt(
                cs.getClusterName().value(),
                user.getName(),
                claims.getAudience(),
                claims.getExpiration(),
                mappedRoles.stream().collect(Collectors.toList()),
                user.getRoles().stream().collect(Collectors.toList()),
                false
            );
        } catch (final Exception ex) {
            logger.error("Error creating OnBehalfOfToken for " + user.getName(), ex);
            throw new OpenSearchSecurityException("Unable to generate OnBehalfOfToken");
        }
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
