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
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.util.SSLRequestHelper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

// TODO: Make Singleton?
public class RestApiPrivilegesEvaluator {

	protected final Logger logger = LogManager.getLogger(this.getClass());

	private final AdminDNs adminDNs;
	private final PrivilegesEvaluator privilegesEvaluator;
	private final PrincipalExtractor principalExtractor;
	private final Path configPath;
	private final ThreadPool threadPool;
	private final Settings settings;

	private final Set<String> allowedRoles = new HashSet<>();

	// endpoints per role, read and cached from settings. Changes here require a
	// node restart, so it's save to cache.
	private final Map<String, Map<Endpoint, List<Method>>> disabledEndpointsForRoles = new HashMap<>();

	// endpoints per user, evaluated and cached dynamically. Changes here
	// require a node restart, so it's save to cache.
	private final Map<String, Map<Endpoint, List<Method>>> disabledEndpointsForUsers = new HashMap<>();

	// globally disabled endpoints and methods, will always be forbidden
	Map<Endpoint, List<Method>> globallyDisabledEndpoints = new HashMap<>();

	// all endpoints and methods, will be returned for users that do not have any access at all
	Map<Endpoint, List<Method>> allEndpoints = new HashMap<>();

	private final Boolean roleBasedAccessEnabled;

	public RestApiPrivilegesEvaluator(final Settings settings,
									  final AdminDNs adminDNs,
									  final PrivilegesEvaluator privilegesEvaluator,
									  final PrincipalExtractor principalExtractor,
									  final Path configPath,
			ThreadPool threadPool) {

		this.adminDNs = adminDNs;
		this.privilegesEvaluator = privilegesEvaluator;
		this.principalExtractor = principalExtractor;
		this.configPath = configPath;
		this.threadPool = threadPool;
		this.settings = settings;
		// set up
		// all endpoints and methods
		Map<Endpoint, List<Method>> allEndpoints = new HashMap<>();
		for(Endpoint endpoint : Endpoint.values()) {
			List<Method> allMethods = new LinkedList<>();
			allMethods.addAll(Arrays.asList(Method.values()));
			allEndpoints.put(endpoint, allMethods);
		}
		this.allEndpoints = Collections.unmodifiableMap(allEndpoints);

		// setup role based permissions
		allowedRoles.addAll(settings.getAsList(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED));

		this.roleBasedAccessEnabled = !allowedRoles.isEmpty();

		// globally disabled endpoints, disables access to Endpoint/Method combination for all roles
		Settings globalSettings = settings.getAsSettings(ConfigConstants.SECURITY_RESTAPI_ENDPOINTS_DISABLED + ".global");
		if (!globalSettings.isEmpty()) {
			globallyDisabledEndpoints = parseDisabledEndpoints(globalSettings);
		}

		final boolean isDebugEnabled = logger.isDebugEnabled();
		if (isDebugEnabled) {
			logger.debug("Globally disabled endpoints: {}", globallyDisabledEndpoints);
		}

		for (String role : allowedRoles) {
			Settings settingsForRole = settings.getAsSettings(ConfigConstants.SECURITY_RESTAPI_ENDPOINTS_DISABLED + "." + role);
			if (settingsForRole.isEmpty()) {
				if (isDebugEnabled) {
					logger.debug("No disabled endpoints/methods for permitted role {} found, allowing all", role);
				}
				continue;
			}
			Map<Endpoint, List<Method>> disabledEndpointsForRole = parseDisabledEndpoints(settingsForRole);
			if (!disabledEndpointsForRole.isEmpty()) {
				disabledEndpointsForRoles.put(role, disabledEndpointsForRole);
			} else {
				logger.warn("Disabled endpoints/methods empty for role {}, please check configuration", role);
			}
		}
		if (logger.isTraceEnabled()) {
			logger.trace("Parsed permission set for endpoints: {}", disabledEndpointsForRoles);
		}
	}

	@SuppressWarnings({ "rawtypes" })
	private Map<Endpoint, List<Method>> parseDisabledEndpoints(Settings settings) {

		// Expects Setting like: 'ACTIONGROUPS=["GET", "POST"]'
		if (settings == null || settings.isEmpty()) {
			logger.error("Settings for disabled endpoint is null or empty: '{}', skipping.", settings);
			return Collections.emptyMap();
		}

		final Map<Endpoint, List<Method>> disabledEndpoints = new HashMap<Endpoint, List<Method>>();

		Map<String, Object> disabledEndpointsSettings = Utils.convertJsonToxToStructuredMap(settings);

		for (Entry<String, Object> value : disabledEndpointsSettings.entrySet()) {
			// key is the endpoint, see if it is a valid one
			String endpointString = value.getKey().toUpperCase();
			Endpoint endpoint = null;
			try {
				endpoint = Endpoint.valueOf(endpointString);
			} catch (Exception e) {
				logger.error("Unknown endpoint '{}' found in configuration, skipping.", endpointString);
				continue;
			}
			// value must be non null
			if (value.getValue() == null) {
				logger.error("Disabled HTTP methods of endpoint '{}' is null, skipping.", endpointString);
				continue;
			}

			// value must be an array of methods
			if (!(value.getValue() instanceof Collection)) {
				logger.error("Disabled HTTP methods of endpoint '{}' must be an array, actually is '{}', skipping.", endpointString, (value.getValue().toString()));
			}
			List<Method> disabledMethods = new LinkedList<>();
			for (Object disabledMethodObj : (Collection) value.getValue()) {
				if (disabledMethodObj == null) {
					logger.error("Found null value in disabled HTTP methods of endpoint '{}', skipping.", endpointString);
					continue;
				}

				if (!(disabledMethodObj instanceof String)) {
					logger.error("Found non-String value in disabled HTTP methods of endpoint '{}', skipping.", endpointString);
					continue;
				}

				String disabledMethodAsString = (String) disabledMethodObj;

				// Provide support for '*', means all methods
				if (disabledMethodAsString.trim().equals("*")) {
					disabledMethods.addAll(Arrays.asList(Method.values()));
					break;
				}
				// no wild card, disabled method must be one of
				// RestRequest.Method
				Method disabledMethod = null;
				try {
					disabledMethod = Method.valueOf(disabledMethodAsString.toUpperCase());
				} catch (Exception e) {
					logger.error("Invalid HTTP method '{}' found in disabled HTTP methods of endpoint '{}', skipping.", disabledMethodAsString.toUpperCase(), endpointString);
					continue;
				}
				disabledMethods.add(disabledMethod);
			}

			disabledEndpoints.put(endpoint, disabledMethods);

		}
		return disabledEndpoints;
	}

	/**
	 * Check if the current request is allowed to use the REST API and the
	 * requested end point. Using an admin certificate grants all permissions. A
	 * user/role can have restricted end points.
	 *
	 * @return an error message if user does not have access, null otherwise
	 *         TODO: log failed attempt in audit log
	 */
	public String checkAccessPermissions(RestRequest request, Endpoint endpoint) throws IOException {

		if (logger.isDebugEnabled()) {
			logger.debug("Checking admin access for endpoint {}, path {} and method {}", endpoint.name(),  request.path(), request.method().name());
		}

		// Grant permission for Account endpoint.
		// Return null to grant access.
		if (endpoint == Endpoint.ACCOUNT) {
			return null;
		}

		String roleBasedAccessFailureReason = checkRoleBasedAccessPermissions(request, endpoint);
		// Role based access granted
		if (roleBasedAccessFailureReason == null) {
			return null;
		}

		String certBasedAccessFailureReason = checkAdminCertBasedAccessPermissions(request);
		// TLS access granted, skip checking roles
		if (certBasedAccessFailureReason == null) {
			return null;
		}


		return constructAccessErrorMessage(roleBasedAccessFailureReason, certBasedAccessFailureReason);
	}

	public Boolean currentUserHasRestApiAccess(Set<String> userRoles) {

		// check if user has any role that grants access
		return !Collections.disjoint(allowedRoles, userRoles);

	}

	public Map<Endpoint, List<Method>> getDisabledEndpointsForCurrentUser(String userPrincipal, Set<String> userRoles) {

		final boolean isDebugEnabled = logger.isDebugEnabled();

		// cache
		if (disabledEndpointsForUsers.containsKey(userPrincipal)) {
			return disabledEndpointsForUsers.get(userPrincipal);
		}

		if (!currentUserHasRestApiAccess(userRoles)) {
			return this.allEndpoints;
		}

		// will contain the final list of disabled endpoints and methods
		Map<Endpoint, List<Method>> finalEndpoints = new HashMap<>();

		// List of all disabled endpoints for user. Disabled endpoints must be configured in all
		// roles to take effect. If a role contains a disabled endpoint, but another role
		// allows this endpoint (i.e. not contained in the disabled endpoints for this role),
		// the access is allowed.

		// make list mutable
		List<Endpoint> remainingEndpoints = new LinkedList<>(Arrays.asList(Endpoint.values()));

		// only retain endpoints contained in all roles for user
		boolean hasDisabledEndpoints = false;
		for (String userRole : userRoles) {
			Map<Endpoint, List<Method>> endpointsForRole = disabledEndpointsForRoles.get(userRole);
			if (endpointsForRole == null || endpointsForRole.isEmpty()) {
				continue;
			}
			Set<Endpoint> disabledEndpoints = endpointsForRole.keySet();
			remainingEndpoints.retainAll(disabledEndpoints);
			hasDisabledEndpoints = true;
		}

		if (isDebugEnabled) {
			logger.debug("Remaining endpoints for user {} after retaining all : {}", userPrincipal, remainingEndpoints);
		}

		// if user does not have any disabled endpoints, only globally disabled endpoints apply
		if (!hasDisabledEndpoints) {

			if (isDebugEnabled) {
				logger.debug("No disabled endpoints for user {} at all,  only globally disabledendpoints apply.", userPrincipal, remainingEndpoints);
			}
			disabledEndpointsForUsers.put(userPrincipal, addGloballyDisabledEndpoints(finalEndpoints));
			return finalEndpoints;

		}

		// one or more disabled remaining endpoints, keep only
		// methods contained in all roles for each endpoint
		for (Endpoint endpoint : remainingEndpoints) {
			// make list mutable
			List<Method> remainingMethodsForEndpoint = new LinkedList<>(Arrays.asList(Method.values()));
			for (String userRole : userRoles) {
				Map<Endpoint, List<Method>> endpoints = disabledEndpointsForRoles.get(userRole);
				if (endpoints != null && !endpoints.isEmpty()) {
					remainingMethodsForEndpoint.retainAll(endpoints.get(endpoint));
				}
			}

			finalEndpoints.put(endpoint, remainingMethodsForEndpoint);
		}

		if (isDebugEnabled) {
			logger.debug("Disabled endpoints for user {} after retaining all : {}", userPrincipal, finalEndpoints);
		}

		// add globally disabled endpoints and methods, will always be disabled
		addGloballyDisabledEndpoints(finalEndpoints);
		disabledEndpointsForUsers.put(userPrincipal, finalEndpoints);

		if (isDebugEnabled) {
			logger.debug("Disabled endpoints for user {} after retaining all : {}", userPrincipal, disabledEndpointsForUsers.get(userPrincipal));
		}

		return disabledEndpointsForUsers.get(userPrincipal);
	}

	private Map<Endpoint, List<Method>> addGloballyDisabledEndpoints(Map<Endpoint, List<Method>> endpoints) {
		if(globallyDisabledEndpoints != null && !globallyDisabledEndpoints.isEmpty()) {
			Set<Endpoint> globalEndoints = globallyDisabledEndpoints.keySet();
			for(Endpoint endpoint : globalEndoints) {
				endpoints.putIfAbsent(endpoint, new LinkedList<>());
				endpoints.get(endpoint).addAll(globallyDisabledEndpoints.get(endpoint));
			}
		}
		return endpoints;
	}

	private String checkRoleBasedAccessPermissions(RestRequest request, Endpoint endpoint) {
		final boolean isTraceEnabled = logger.isTraceEnabled();
		if (isTraceEnabled) {
			logger.trace("Checking role based admin access for endpoint {} and method {}", endpoint.name(), request.method().name());
		}
		final boolean isDebugEnabled = logger.isDebugEnabled();
		// Role based access. Check that user has role suitable for admin access
		// and that the role has also access to this endpoint.
		if (this.roleBasedAccessEnabled) {

			// get current user and roles
			final Pair<User, TransportAddress> userAndRemoteAddress =
					Utils.userAndRemoteAddressFrom(threadPool.getThreadContext());
			final User user = userAndRemoteAddress.getLeft();
			final TransportAddress remoteAddress = userAndRemoteAddress.getRight();

			// map the users Security roles
			Set<String> userRoles = privilegesEvaluator.mapRoles(user, remoteAddress);

			// check if user has any role that grants access
			if (currentUserHasRestApiAccess(userRoles)) {
				// yes, calculate disabled end points. Since a user can have
				// multiple roles, the endpoint
				// needs to be disabled in all roles.
				Map<Endpoint, List<Method>> disabledEndpointsForUser = getDisabledEndpointsForCurrentUser(user.getName(), userRoles);

				if (isDebugEnabled) {
					logger.debug("Disabled endpoints for user {} : {} ", user, disabledEndpointsForUser);
				}

				// check if we have any disabled methods for this endpoint
				List<Method> disabledMethodsForEndpoint = disabledEndpointsForUser.get(endpoint);

				// no settings, all methods for this endpoint allowed
				if (disabledMethodsForEndpoint == null || disabledMethodsForEndpoint.isEmpty()) {
					if (isDebugEnabled) {
						logger.debug("No disabled methods for user {} and endpoint {}, access allowed ", user, endpoint);
					}
					return null;
				}

				// some methods disabled, check requested method
				if (!disabledMethodsForEndpoint.contains(request.method())) {
					if (isDebugEnabled) {
						logger.debug("Request method {} for user {} and endpoint {} not restricted, access allowed ", request.method(), user, endpoint);
					}
					return null;
				}

				logger.info("User {} with Security roles {} does not have access to endpoint {} and method {}, checking admin TLS certificate now.", user, userRoles,
						endpoint.name(), request.method());
				return "User " + user.getName() + " with Security roles " + userRoles + " does not have any access to endpoint " + endpoint.name() + " and method "
						+ request.method().name();
			} else {
				// no, but maybe the request contains a client certificate.
				// Remember error reason for better response message later on.
				logger.info("User {} with Security roles {} does not have any role privileged for admin access.", user, userRoles);
				return "User " + user.getName() + " with Security roles " + userRoles + " does not have any role privileged for admin access";
			}
		}
		return "Role based access not enabled.";
	}

	private String checkAdminCertBasedAccessPermissions(RestRequest request) throws IOException {
		if (logger.isTraceEnabled()) {
			logger.trace("Checking certificate based admin access for path {} and method {}", request.path(), request.method().name());
		}

		// Certificate based access, Check if we have an admin TLS certificate
		SSLRequestHelper.SSLInfo sslInfo = SSLRequestHelper.getSSLInfo(settings, configPath, request, principalExtractor);

		if (sslInfo == null) {
			// here we log on error level, since authentication finally failed
			logger.warn("No ssl info found in request.");
			return "No ssl info found in request.";
		}

		X509Certificate[] certs = sslInfo.getX509Certs();

		if (certs == null || certs.length == 0) {
			logger.warn("No client TLS certificate found in request");
			return "No client TLS certificate found in request";
		}

		if (!adminDNs.isAdminDN(sslInfo.getPrincipal())) {
			logger.warn("Security admin permissions required but {} is not an admin", sslInfo.getPrincipal());
			return "Security admin permissions required but " + sslInfo.getPrincipal() + " is not an admin";
		}
		return null;
	}

	private String constructAccessErrorMessage(String roleBasedAccessFailure, String certBasedAccessFailure) {
		return roleBasedAccessFailure + ". " + certBasedAccessFailure;
	}

}
