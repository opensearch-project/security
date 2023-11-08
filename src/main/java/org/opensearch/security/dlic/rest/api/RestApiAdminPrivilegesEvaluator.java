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

package org.opensearch.security.dlic.rest.api;

import java.util.Locale;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;

public class RestApiAdminPrivilegesEvaluator {

    protected final Logger logger = LogManager.getLogger(RestApiAdminPrivilegesEvaluator.class);

    public final static String CERTS_INFO_ACTION = "certs/info";

    public final static String RELOAD_CERTS_ACTION = "certs/reload";

    public final static String SECURITY_CONFIG_UPDATE = "update";

    private final static String REST_API_PERMISSION_PREFIX = "restapi:admin";

    private final static String REST_ENDPOINT_PERMISSION_PATTERN = REST_API_PERMISSION_PREFIX + "/%s";

    private final static String REST_ENDPOINT_ACTION_PERMISSION_PATTERN = REST_API_PERMISSION_PREFIX + "/%s/%s";

    private final static WildcardMatcher REST_API_PERMISSION_PREFIX_MATCHER = WildcardMatcher.from(REST_API_PERMISSION_PREFIX + "/*");

    @FunctionalInterface
    public interface PermissionBuilder {

        default String build() {
            return build(null);
        }

        String build(final String action);

    }

    public final static Map<Endpoint, PermissionBuilder> ENDPOINTS_WITH_PERMISSIONS = ImmutableMap.<Endpoint, PermissionBuilder>builder()
        .put(Endpoint.ACTIONGROUPS, action -> buildEndpointPermission(Endpoint.ACTIONGROUPS))
        .put(Endpoint.ALLOWLIST, action -> buildEndpointPermission(Endpoint.ALLOWLIST))
        .put(Endpoint.CONFIG, action -> buildEndpointActionPermission(Endpoint.CONFIG, action))
        .put(Endpoint.INTERNALUSERS, action -> buildEndpointPermission(Endpoint.INTERNALUSERS))
        .put(Endpoint.NODESDN, action -> buildEndpointPermission(Endpoint.NODESDN))
        .put(Endpoint.ROLES, action -> buildEndpointPermission(Endpoint.ROLES))
        .put(Endpoint.ROLESMAPPING, action -> buildEndpointPermission(Endpoint.ROLESMAPPING))
        .put(Endpoint.TENANTS, action -> buildEndpointPermission(Endpoint.TENANTS))
        .put(Endpoint.SSL, action -> buildEndpointActionPermission(Endpoint.SSL, action))
        .build();

    private final ThreadContext threadContext;

    private final PrivilegesEvaluator privilegesEvaluator;

    private final AdminDNs adminDNs;

    private final boolean restapiAdminEnabled;

    public RestApiAdminPrivilegesEvaluator(
        final ThreadContext threadContext,
        final PrivilegesEvaluator privilegesEvaluator,
        final AdminDNs adminDNs,
        final boolean restapiAdminEnabled
    ) {
        this.threadContext = threadContext;
        this.privilegesEvaluator = privilegesEvaluator;
        this.adminDNs = adminDNs;
        this.restapiAdminEnabled = restapiAdminEnabled;
    }

    public boolean isCurrentUserAdminFor(final Endpoint endpoint, final String action) {
        final Pair<User, TransportAddress> userAndRemoteAddress = Utils.userAndRemoteAddressFrom(threadContext);
        if (userAndRemoteAddress.getLeft() == null) {
            return false;
        }
        if (adminDNs.isAdmin(userAndRemoteAddress.getLeft())) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                    "Security admin permissions required for endpoint {} but {} is not an admin",
                    endpoint,
                    userAndRemoteAddress.getLeft().getName()
                );
            }
            return true;
        }
        if (!ENDPOINTS_WITH_PERMISSIONS.containsKey(endpoint)) {
            logger.debug("No permission found for {} endpoint", endpoint);
            return false;
        }
        final String permission = ENDPOINTS_WITH_PERMISSIONS.get(endpoint).build(action);
        final boolean hasAccess = privilegesEvaluator.hasRestAdminPermissions(
            userAndRemoteAddress.getLeft(),
            userAndRemoteAddress.getRight(),
            permission
        );
        if (logger.isDebugEnabled()) {
            logger.debug(
                "User {} with permission {} {} access to endpoint {}",
                userAndRemoteAddress.getLeft().getName(),
                permission,
                hasAccess ? "has" : "has no",
                endpoint
            );
            logger.debug(
                "{} set to {}. {} use access decision",
                SECURITY_RESTAPI_ADMIN_ENABLED,
                restapiAdminEnabled,
                restapiAdminEnabled ? "Will" : "Will not"
            );
        }
        return hasAccess && restapiAdminEnabled;
    }

    public boolean containsRestApiAdminPermissions(final Object configObject) {
        if (configObject == null) {
            return false;
        }
        if (configObject instanceof RoleV7) {
            return ((RoleV7) configObject).getCluster_permissions().stream().anyMatch(REST_API_PERMISSION_PREFIX_MATCHER);
        } else if (configObject instanceof ActionGroupsV7) {
            return ((ActionGroupsV7) configObject).getAllowed_actions().stream().anyMatch(REST_API_PERMISSION_PREFIX_MATCHER);
        } else {
            return false;
        }
    }

    public boolean isCurrentUserAdminFor(final Endpoint endpoint) {
        return isCurrentUserAdminFor(endpoint, null);
    }

    private static String buildEndpointActionPermission(final Endpoint endpoint, final String action) {
        return String.format(REST_ENDPOINT_ACTION_PERMISSION_PATTERN, endpoint.name().toLowerCase(Locale.ROOT), action);
    }

    private static String buildEndpointPermission(final Endpoint endpoint) {
        return String.format(REST_ENDPOINT_PERMISSION_PATTERN, endpoint.name().toLowerCase(Locale.ROOT));
    }

}
