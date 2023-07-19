/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.filter;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLPeerUnverifiedException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.greenrobot.eventbus.Subscribe;

import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.CompatConfig;
import org.opensearch.security.dlic.rest.api.AllowlistApiAction;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.RestLayerPrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.AllowlistingSettings;
import org.opensearch.security.securityconf.impl.WhitelistingSettings;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.ssl.util.SSLRequestHelper;
import org.opensearch.security.ssl.util.SSLRequestHelper.SSLInfo;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HTTPHelper;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class SecurityRestFilter {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final BackendRegistry registry;
    private final RestLayerPrivilegesEvaluator evaluator;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    private final PrincipalExtractor principalExtractor;
    private final Settings settings;
    private final Path configPath;
    private final CompatConfig compatConfig;

    private WhitelistingSettings whitelistingSettings;
    private AllowlistingSettings allowlistingSettings;

    private static final String HEALTH_SUFFIX = "health";
    private static final String WHO_AM_I_SUFFIX = "whoami";

    private static final String REGEX_PATH_PREFIX = "/(" + LEGACY_OPENDISTRO_PREFIX + "|" + PLUGINS_PREFIX + ")/" + "(.*)";
    private static final Pattern PATTERN_PATH_PREFIX = Pattern.compile(REGEX_PATH_PREFIX);

    public SecurityRestFilter(
        final BackendRegistry registry,
        final RestLayerPrivilegesEvaluator evaluator,
        final AuditLog auditLog,
        final ThreadPool threadPool,
        final PrincipalExtractor principalExtractor,
        final Settings settings,
        final Path configPath,
        final CompatConfig compatConfig
    ) {
        super();
        this.registry = registry;
        this.evaluator = evaluator;
        this.auditLog = auditLog;
        this.threadContext = threadPool.getThreadContext();
        this.principalExtractor = principalExtractor;
        this.settings = settings;
        this.configPath = configPath;
        this.compatConfig = compatConfig;
        this.whitelistingSettings = new WhitelistingSettings();
        this.allowlistingSettings = new AllowlistingSettings();
    }

    /**
     * This function wraps around all rest requests
     * If the request is authenticated, then it goes through a allowlisting check.
     * The allowlisting check works as follows:
     * If allowlisting is not enabled, then requests are handled normally.
     * If allowlisting is enabled, then SuperAdmin is allowed access to all APIs, regardless of what is currently allowlisted.
     * If allowlisting is enabled, then Non-SuperAdmin is allowed to access only those APIs that are allowlisted in {@link #requests}
     * For example: if allowlisting is enabled and requests = ["/_cat/nodes"], then SuperAdmin can access all APIs, but non SuperAdmin
     * can only access "/_cat/nodes"
     * Further note: Some APIs are only accessible by SuperAdmin, regardless of allowlisting. For example: /_opendistro/_security/api/whitelist is only accessible by SuperAdmin.
     * See {@link AllowlistApiAction} for the implementation of this API.
     * SuperAdmin is identified by credentials, which can be passed in the curl request.
     */
    public RestHandler wrap(RestHandler original, AdminDNs adminDNs) {
        return (request, channel, client) -> {
            org.apache.logging.log4j.ThreadContext.clearAll();
            if (!checkAndAuthenticateRequest(request, channel)) {
                User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                boolean isSuperAdminUser = userIsSuperAdmin(user, adminDNs);
                if (isSuperAdminUser
                    || (whitelistingSettings.checkRequestIsAllowed(request, channel, client)
                        && allowlistingSettings.checkRequestIsAllowed(request, channel, client))) {
                    if (isSuperAdminUser || authorizeRequest(original, request, channel, user)) {
                        original.handleRequest(request, channel, client);
                    }
                }
            }
        };
    }

    /**
     * Checks if a given user is a SuperAdmin
     */
    private boolean userIsSuperAdmin(User user, AdminDNs adminDNs) {
        return user != null && adminDNs.isAdmin(user);
    }

    private boolean authorizeRequest(RestHandler original, RestRequest request, RestChannel channel, User user) {

        List<RestHandler.Route> restRoutes = original.routes();
        Optional<RestHandler.Route> handler = restRoutes.stream()
            .filter(rh -> rh.getMethod().equals(request.method()))
            .filter(rh -> restPathMatches(request.path(), rh.getPath()))
            .findFirst();
        final boolean routeSupportsRestAuthorization = handler.isPresent() && handler.get() instanceof NamedRoute;
        if (routeSupportsRestAuthorization) {
            PrivilegesEvaluatorResponse pres = new PrivilegesEvaluatorResponse();
            NamedRoute route = ((NamedRoute) handler.get());
            // if actionNames are present evaluate those first
            Set<String> actionNames = route.actionNames();
            if (actionNames != null && !actionNames.isEmpty()) {
                pres = evaluator.evaluate(user, actionNames);
            }

            // now if pres.allowed is still false check for the NamedRoute name as a permission
            if (!pres.isAllowed()) {
                String action = route.name();
                pres = evaluator.evaluate(user, Set.of(action));
            }

            if (log.isDebugEnabled()) {
                log.debug(pres.toString());
            }
            if (pres.isAllowed()) {
                log.debug("Request has been granted");
                auditLog.logGrantedPrivileges(user.getName(), request);
            } else {
                auditLog.logMissingPrivileges(route.name(), user.getName(), request);
                String err;
                if (!pres.getMissingSecurityRoles().isEmpty()) {
                    err = String.format("No mapping for %s on roles %s", user, pres.getMissingSecurityRoles());
                } else {
                    err = String.format("no permissions for %s and %s", pres.getMissingPrivileges(), user);
                }
                log.debug(err);
                channel.sendResponse(new BytesRestResponse(RestStatus.UNAUTHORIZED, err));
                return false;
            }
        }

        // if handler is not an instance of NamedRoute then we pass through to eval at Transport Layer.
        return true;
    }

    private boolean checkAndAuthenticateRequest(RestRequest request, RestChannel channel) throws Exception {

        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, Origin.REST.toString());

        if (HTTPHelper.containsBadHeader(request)) {
            final OpenSearchException exception = ExceptionUtils.createBadHeaderException();
            log.error(exception.toString());
            auditLog.logBadHeaders(request);
            channel.sendResponse(new BytesRestResponse(channel, RestStatus.FORBIDDEN, exception));
            return true;
        }

        if (SSLRequestHelper.containsBadHeader(threadContext, ConfigConstants.OPENDISTRO_SECURITY_CONFIG_PREFIX)) {
            final OpenSearchException exception = ExceptionUtils.createBadHeaderException();
            log.error(exception.toString());
            auditLog.logBadHeaders(request);
            channel.sendResponse(new BytesRestResponse(channel, RestStatus.FORBIDDEN, exception));
            return true;
        }

        final SSLInfo sslInfo;
        try {
            if ((sslInfo = SSLRequestHelper.getSSLInfo(settings, configPath, request, principalExtractor)) != null) {
                if (sslInfo.getPrincipal() != null) {
                    threadContext.putTransient("_opendistro_security_ssl_principal", sslInfo.getPrincipal());
                }

                if (sslInfo.getX509Certs() != null) {
                    threadContext.putTransient("_opendistro_security_ssl_peer_certificates", sslInfo.getX509Certs());
                }
                threadContext.putTransient("_opendistro_security_ssl_protocol", sslInfo.getProtocol());
                threadContext.putTransient("_opendistro_security_ssl_cipher", sslInfo.getCipher());
            }
        } catch (SSLPeerUnverifiedException e) {
            log.error("No ssl info", e);
            auditLog.logSSLException(request, e);
            channel.sendResponse(new BytesRestResponse(channel, RestStatus.FORBIDDEN, e));
            return true;
        }

        if (!compatConfig.restAuthEnabled()) {
            return false;
        }

        Matcher matcher = PATTERN_PATH_PREFIX.matcher(request.path());
        final String suffix = matcher.matches() ? matcher.group(2) : null;
        if (request.method() != Method.OPTIONS && !(HEALTH_SUFFIX.equals(suffix)) && !(WHO_AM_I_SUFFIX.equals(suffix))) {
            if (!registry.authenticate(request, channel, threadContext)) {
                // another roundtrip
                org.apache.logging.log4j.ThreadContext.remove("user");
                return true;
            } else {
                // make it possible to filter logs by username
                org.apache.logging.log4j.ThreadContext.put(
                    "user",
                    ((User) threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER)).getName()
                );
            }
        }

        return false;
    }

    @Subscribe
    public void onWhitelistingSettingChanged(WhitelistingSettings whitelistingSettings) {
        this.whitelistingSettings = whitelistingSettings;
    }

    @Subscribe
    public void onAllowlistingSettingChanged(AllowlistingSettings allowlistingSettings) {
        this.allowlistingSettings = allowlistingSettings;
    }

    /**
     * Determines if the request's path is a match for the configured handler path.
     *
     * @param requestPath The path from the {@link NamedRoute}
     * @param handlerPath The path from the {@link RestHandler.Route}
     * @return true if the request path matches the route
     */
    private boolean restPathMatches(String requestPath, String handlerPath) {
        // Check exact match
        if (handlerPath.equals(requestPath)) {
            return true;
        }
        // Split path to evaluate named params
        String[] handlerSplit = handlerPath.split("/");
        String[] requestSplit = requestPath.split("/");
        if (handlerSplit.length != requestSplit.length) {
            return false;
        }
        for (int i = 0; i < handlerSplit.length; i++) {
            if (!(handlerSplit[i].equals(requestSplit[i]) || (handlerSplit[i].startsWith("{") && handlerSplit[i].endsWith("}")))) {
                return false;
            }
        }
        return true;
    }
}
