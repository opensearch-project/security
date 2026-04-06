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

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityRequestFactory;
import org.opensearch.security.privileges.PrivilegesConfiguration;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.RoleMapper;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.util.SSLRequestHelper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;

public class RestApiAuthorizationEvaluator {

    protected final Logger logger = LogManager.getLogger(this.getClass());

    public static final String CERTS_INFO_ACTION = "certs/info";

    public static final String RELOAD_CERTS_ACTION = "certs/reload";

    public static final String SECURITY_CONFIG_UPDATE = "update";

    public static final String RESOURCE_MIGRATE_ACTION = "migrate";

    private static final String REST_API_PERMISSION_PREFIX = "restapi:admin";

    private static final String REST_ENDPOINT_PERMISSION_PATTERN = REST_API_PERMISSION_PREFIX + "/%s";

    private static final String REST_ENDPOINT_ACTION_PERMISSION_PATTERN = REST_API_PERMISSION_PREFIX + "/%s/%s";

    private static final WildcardMatcher REST_API_PERMISSION_PREFIX_MATCHER = WildcardMatcher.from(REST_API_PERMISSION_PREFIX + "/*");

    @FunctionalInterface
    public interface PermissionBuilder {

        default String build() {
            return build(null);
        }

        String build(final String action);

    }

    public static final Map<Endpoint, PermissionBuilder> ENDPOINTS_WITH_PERMISSIONS = ImmutableMap.<Endpoint, PermissionBuilder>builder()
        .put(Endpoint.ACTIONGROUPS, action -> buildEndpointPermission(Endpoint.ACTIONGROUPS))
        .put(Endpoint.ALLOWLIST, action -> buildEndpointPermission(Endpoint.ALLOWLIST))
        .put(Endpoint.CONFIG, action -> buildEndpointActionPermission(Endpoint.CONFIG, action))
        .put(Endpoint.INTERNALUSERS, action -> buildEndpointPermission(Endpoint.INTERNALUSERS))
        .put(Endpoint.NODESDN, action -> buildEndpointPermission(Endpoint.NODESDN))
        .put(Endpoint.RATELIMITERS, action -> buildEndpointPermission(Endpoint.RATELIMITERS))
        .put(Endpoint.ROLES, action -> buildEndpointPermission(Endpoint.ROLES))
        .put(Endpoint.ROLESMAPPING, action -> buildEndpointPermission(Endpoint.ROLESMAPPING))
        .put(Endpoint.TENANTS, action -> buildEndpointPermission(Endpoint.TENANTS))
        .put(Endpoint.VIEW_VERSION, action -> buildEndpointPermission(Endpoint.VIEW_VERSION))
        .put(Endpoint.ROLLBACK_VERSION, action -> buildEndpointPermission(Endpoint.ROLLBACK_VERSION))
        .put(Endpoint.SSL, action -> buildEndpointActionPermission(Endpoint.SSL, action))
        .put(Endpoint.RESOURCE_SHARING, action -> buildEndpointActionPermission(Endpoint.RESOURCE_SHARING, action))
        .build();

    private final AdminDNs adminDNs;
    private final RoleMapper roleMapper;
    private final PrincipalExtractor principalExtractor;
    private final Path configPath;
    private final ThreadPool threadPool;
    private final Settings settings;
    private final ThreadContext threadContext;
    private final PrivilegesConfiguration privilegesConfiguration;
    private final boolean restapiAdminEnabled;

    private final Set<String> allowedRoles = new HashSet<>();

    private final Map<String, Map<Endpoint, List<Method>>> disabledEndpointsForRoles = new HashMap<>();

    private final Map<String, Map<Endpoint, List<Method>>> disabledEndpointsForUsers = new HashMap<>();

    Map<Endpoint, List<Method>> globallyDisabledEndpoints = new HashMap<>();

    Map<Endpoint, List<Method>> allEndpoints = new HashMap<>();

    private final boolean roleBasedAccessEnabled;

    public RestApiAuthorizationEvaluator(
        final Settings settings,
        final AdminDNs adminDNs,
        final RoleMapper roleMapper,
        final PrincipalExtractor principalExtractor,
        final Path configPath,
        final ThreadPool threadPool,
        final PrivilegesConfiguration privilegesConfiguration
    ) {
        this.adminDNs = adminDNs;
        this.roleMapper = roleMapper;
        this.principalExtractor = principalExtractor;
        this.configPath = configPath;
        this.threadPool = threadPool;
        this.threadContext = threadPool.getThreadContext();
        this.settings = settings;
        this.privilegesConfiguration = privilegesConfiguration;
        this.restapiAdminEnabled = settings.getAsBoolean(SECURITY_RESTAPI_ADMIN_ENABLED, false);

        final Map<Endpoint, List<Method>> allEndpoints = new HashMap<>();
        for (Endpoint endpoint : Endpoint.values()) {
            final List<Method> allMethods = new LinkedList<>();
            allMethods.addAll(Arrays.asList(Method.values()));
            allEndpoints.put(endpoint, allMethods);
        }
        this.allEndpoints = Collections.unmodifiableMap(allEndpoints);

        allowedRoles.addAll(settings.getAsList(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED));
        this.roleBasedAccessEnabled = allowedRoles.isEmpty() == false;

        final Settings globalSettings = settings.getAsSettings(ConfigConstants.SECURITY_RESTAPI_ENDPOINTS_DISABLED + ".global");
        if (globalSettings.isEmpty() == false) {
            globallyDisabledEndpoints = parseDisabledEndpoints(globalSettings);
        }

        final boolean isDebugEnabled = logger.isDebugEnabled();
        if (isDebugEnabled) {
            logger.debug("Globally disabled endpoints: {}", globallyDisabledEndpoints);
        }

        for (String role : allowedRoles) {
            final Settings settingsForRole = settings.getAsSettings(ConfigConstants.SECURITY_RESTAPI_ENDPOINTS_DISABLED + "." + role);
            if (settingsForRole.isEmpty()) {
                if (isDebugEnabled) {
                    logger.debug("No disabled endpoints/methods for permitted role {} found, allowing all", role);
                }
                continue;
            }

            final Map<Endpoint, List<Method>> disabledEndpointsForRole = parseDisabledEndpoints(settingsForRole);
            if (disabledEndpointsForRole.isEmpty() == false) {
                disabledEndpointsForRoles.put(role, disabledEndpointsForRole);
            } else {
                logger.warn("Disabled endpoints/methods empty for role {}, please check configuration", role);
            }
        }

        if (logger.isTraceEnabled()) {
            logger.trace("Parsed permission set for endpoints: {}", disabledEndpointsForRoles);
        }
    }

    public String checkAccessPermissions(RestRequest request, Endpoint endpoint) throws IOException {

        if (logger.isDebugEnabled()) {
            logger.debug(
                "Checking admin access for endpoint {}, path {} and method {}",
                endpoint.name(),
                request.path(),
                request.method().name()
            );
        }

        if (endpoint == Endpoint.ACCOUNT) {
            return null;
        }

        final String roleBasedAccessFailureReason = checkRoleBasedAccessPermissions(request, endpoint);
        if (roleBasedAccessFailureReason == null) {
            return null;
        }

        final String certBasedAccessFailureReason = checkAdminCertBasedAccessPermissions(request);
        if (certBasedAccessFailureReason == null) {
            return null;
        }

        return constructAccessErrorMessage(roleBasedAccessFailureReason, certBasedAccessFailureReason);
    }

    public boolean isCurrentUserAdminFor(final Endpoint endpoint, final String action) {
        final Pair<User, TransportAddress> userAndRemoteAddress = Utils.userAndRemoteAddressFrom(threadContext);
        if (userAndRemoteAddress.getLeft() == null) {
            return false;
        }
        if (adminDNs.isAdmin(userAndRemoteAddress.getLeft())) {
            return true;
        }
        if (ENDPOINTS_WITH_PERMISSIONS.containsKey(endpoint) == false) {
            logger.debug("No permission found for {} endpoint", endpoint);
            return false;
        }
        final String permission = ENDPOINTS_WITH_PERMISSIONS.get(endpoint).build(action);
        final PrivilegesEvaluationContext context = privilegesConfiguration.privilegesEvaluator()
            .createContext(userAndRemoteAddress.getLeft(), permission);
        final boolean hasAccess = context.getActionPrivileges().hasExplicitClusterPrivilege(context, permission).isAllowed();

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

    public boolean isCurrentUserAdminFor(final Endpoint endpoint) {
        return isCurrentUserAdminFor(endpoint, null);
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

    public boolean currentUserHasRestApiAccess(Set<String> userRoles) {
        return Collections.disjoint(allowedRoles, userRoles) == false;
    }

    public Map<Endpoint, List<Method>> getDisabledEndpointsForCurrentUser(String userPrincipal, Set<String> userRoles) {

        final boolean isDebugEnabled = logger.isDebugEnabled();

        if (disabledEndpointsForUsers.containsKey(userPrincipal)) {
            return disabledEndpointsForUsers.get(userPrincipal);
        }

        if (!currentUserHasRestApiAccess(userRoles)) {
            return this.allEndpoints;
        }

        final Map<Endpoint, List<Method>> finalEndpoints = new HashMap<>();
        final List<Endpoint> remainingEndpoints = new LinkedList<>(Arrays.asList(Endpoint.values()));

        boolean hasDisabledEndpoints = false;
        for (String userRole : userRoles) {
            final Map<Endpoint, List<Method>> endpointsForRole = disabledEndpointsForRoles.get(userRole);
            if (endpointsForRole == null || endpointsForRole.isEmpty()) {
                continue;
            }
            remainingEndpoints.retainAll(endpointsForRole.keySet());
            hasDisabledEndpoints = true;
        }

        if (isDebugEnabled) {
            logger.debug("Remaining endpoints for user {} after retaining all : {}", userPrincipal, remainingEndpoints);
        }

        if (hasDisabledEndpoints == false) {
            if (isDebugEnabled) {
                logger.debug(
                    "No disabled endpoints for user {} at all,  only globally disabledendpoints apply.",
                    userPrincipal,
                    remainingEndpoints
                );
            }
            disabledEndpointsForUsers.put(userPrincipal, addGloballyDisabledEndpoints(finalEndpoints));
            return finalEndpoints;
        }

        for (Endpoint endpoint : remainingEndpoints) {
            final List<Method> remainingMethodsForEndpoint = new LinkedList<>(Arrays.asList(Method.values()));
            for (String userRole : userRoles) {
                final Map<Endpoint, List<Method>> endpoints = disabledEndpointsForRoles.get(userRole);
                if (endpoints != null && endpoints.isEmpty() == false) {
                    remainingMethodsForEndpoint.retainAll(endpoints.get(endpoint));
                }
            }

            finalEndpoints.put(endpoint, remainingMethodsForEndpoint);
        }

        if (isDebugEnabled) {
            logger.debug("Disabled endpoints for user {} after retaining all : {}", userPrincipal, finalEndpoints);
        }

        addGloballyDisabledEndpoints(finalEndpoints);
        disabledEndpointsForUsers.put(userPrincipal, finalEndpoints);

        if (isDebugEnabled) {
            logger.debug(
                "Disabled endpoints for user {} after retaining all : {}",
                userPrincipal,
                disabledEndpointsForUsers.get(userPrincipal)
            );
        }

        return disabledEndpointsForUsers.get(userPrincipal);
    }

    @SuppressWarnings({ "rawtypes" })
    private Map<Endpoint, List<Method>> parseDisabledEndpoints(Settings settings) {
        if (settings == null || settings.isEmpty()) {
            logger.error("Settings for disabled endpoint is null or empty: '{}', skipping.", settings);
            return Collections.emptyMap();
        }

        final Map<Endpoint, List<Method>> disabledEndpoints = new HashMap<>();
        final Map<String, Object> disabledEndpointsSettings = Utils.convertJsonToxToStructuredMap(settings);

        for (Entry<String, Object> value : disabledEndpointsSettings.entrySet()) {
            final String endpointString = value.getKey().toUpperCase();
            final Endpoint endpoint;
            try {
                endpoint = Endpoint.valueOf(endpointString);
            } catch (Exception e) {
                logger.error("Unknown endpoint '{}' found in configuration, skipping.", endpointString);
                continue;
            }

            if (value.getValue() == null) {
                logger.error("Disabled HTTP methods of endpoint '{}' is null, skipping.", endpointString);
                continue;
            }

            if (value.getValue() instanceof Collection == false) {
                logger.error(
                    "Disabled HTTP methods of endpoint '{}' must be an array, actually is '{}', skipping.",
                    endpointString,
                    (value.getValue().toString())
                );
            }

            final List<Method> disabledMethods = new LinkedList<>();
            for (Object disabledMethodObj : (Collection) value.getValue()) {
                if (disabledMethodObj == null) {
                    logger.error("Found null value in disabled HTTP methods of endpoint '{}', skipping.", endpointString);
                    continue;
                }

                if (disabledMethodObj instanceof String == false) {
                    logger.error("Found non-String value in disabled HTTP methods of endpoint '{}', skipping.", endpointString);
                    continue;
                }

                final String disabledMethodAsString = (String) disabledMethodObj;

                if (disabledMethodAsString.trim().equals("*")) {
                    disabledMethods.addAll(Arrays.asList(Method.values()));
                    break;
                }

                try {
                    disabledMethods.add(Method.valueOf(disabledMethodAsString.toUpperCase()));
                } catch (Exception e) {
                    logger.error(
                        "Invalid HTTP method '{}' found in disabled HTTP methods of endpoint '{}', skipping.",
                        disabledMethodAsString.toUpperCase(),
                        endpointString
                    );
                }
            }

            disabledEndpoints.put(endpoint, disabledMethods);
        }

        return disabledEndpoints;
    }

    private Map<Endpoint, List<Method>> addGloballyDisabledEndpoints(Map<Endpoint, List<Method>> endpoints) {
        if (globallyDisabledEndpoints != null && globallyDisabledEndpoints.isEmpty() == false) {
            final Set<Endpoint> globalEndpoints = globallyDisabledEndpoints.keySet();
            for (Endpoint endpoint : globalEndpoints) {
                endpoints.putIfAbsent(endpoint, new LinkedList<>());
                endpoints.get(endpoint).addAll(globallyDisabledEndpoints.get(endpoint));
            }
        }
        return endpoints;
    }

    private String checkRoleBasedAccessPermissions(RestRequest request, Endpoint endpoint) {
        if (logger.isTraceEnabled()) {
            logger.trace("Checking role based admin access for endpoint {} and method {}", endpoint.name(), request.method().name());
        }
        final boolean isDebugEnabled = logger.isDebugEnabled();
        if (this.roleBasedAccessEnabled) {
            final Pair<User, TransportAddress> userAndRemoteAddress = Utils.userAndRemoteAddressFrom(threadPool.getThreadContext());
            final User user = userAndRemoteAddress.getLeft();
            final TransportAddress remoteAddress = userAndRemoteAddress.getRight();

            final Set<String> userRoles = roleMapper.map(user, remoteAddress);

            if (currentUserHasRestApiAccess(userRoles)) {
                final Map<Endpoint, List<Method>> disabledEndpointsForUser = getDisabledEndpointsForCurrentUser(user.getName(), userRoles);

                if (isDebugEnabled) {
                    logger.debug("Disabled endpoints for user {} : {} ", user, disabledEndpointsForUser);
                }

                final List<Method> disabledMethodsForEndpoint = disabledEndpointsForUser.get(endpoint);
                if (disabledMethodsForEndpoint == null || disabledMethodsForEndpoint.isEmpty()) {
                    if (isDebugEnabled) {
                        logger.debug("No disabled methods for user {} and endpoint {}, access allowed ", user, endpoint);
                    }
                    return null;
                }

                if (disabledMethodsForEndpoint.contains(request.method()) == false) {
                    if (isDebugEnabled) {
                        logger.debug(
                            "Request method {} for user {} and endpoint {} not restricted, access allowed ",
                            request.method(),
                            user,
                            endpoint
                        );
                    }
                    return null;
                }

                logger.info(
                    "User {} with Security roles {} does not have access to endpoint {} and method {}, checking admin TLS certificate now.",
                    user,
                    userRoles,
                    endpoint.name(),
                    request.method()
                );
                return "User "
                    + user.getName()
                    + " with Security roles "
                    + userRoles
                    + " does not have any access to endpoint "
                    + endpoint.name()
                    + " and method "
                    + request.method().name();
            } else {
                logger.info("User {} with Security roles {} does not have any role privileged for admin access.", user, userRoles);
                return "User "
                    + user.getName()
                    + " with Security roles "
                    + userRoles
                    + " does not have any role privileged for admin access";
            }
        }
        return "Role based access not enabled.";
    }

    private String checkAdminCertBasedAccessPermissions(RestRequest request) throws IOException {
        if (logger.isTraceEnabled()) {
            logger.trace("Checking certificate based admin access for path {} and method {}", request.path(), request.method().name());
        }

        final SecurityRequest securityRequest = SecurityRequestFactory.from(request);
        final SSLRequestHelper.SSLInfo sslInfo = SSLRequestHelper.getSSLInfo(settings, configPath, securityRequest, principalExtractor);

        if (sslInfo == null) {
            logger.warn("No ssl info found in request.");
            return "No ssl info found in request.";
        }

        final X509Certificate[] certs = sslInfo.getX509Certs();

        if (certs == null || certs.length == 0) {
            logger.warn("No client TLS certificate found in request");
            return "No client TLS certificate found in request";
        }

        if (adminDNs.isAdminDN(sslInfo.getPrincipal()) == false) {
            logger.warn("Security admin permissions required but {} is not an admin", sslInfo.getPrincipal());
            return "Security admin permissions required but " + sslInfo.getPrincipal() + " is not an admin";
        }
        return null;
    }

    private String constructAccessErrorMessage(String roleBasedAccessFailure, String certBasedAccessFailure) {
        return roleBasedAccessFailure + ". " + certBasedAccessFailure;
    }

    private static String buildEndpointActionPermission(final Endpoint endpoint, final String action) {
        return String.format(REST_ENDPOINT_ACTION_PERMISSION_PATTERN, endpoint.name().toLowerCase(Locale.ROOT), action);
    }

    private static String buildEndpointPermission(final Endpoint endpoint) {
        return String.format(REST_ENDPOINT_PERMISSION_PATTERN, endpoint.name().toLowerCase(Locale.ROOT));
    }
}
