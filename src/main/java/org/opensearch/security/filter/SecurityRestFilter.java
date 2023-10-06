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
 * Portions Copyright OpenSearch Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package org.opensearch.security.filter;

import java.nio.file.Path;

import javax.net.ssl.SSLPeerUnverifiedException;

import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.rest.RestHandler;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.CompatConfig;
import org.opensearch.security.securityconf.impl.WhitelistingSettings;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.ssl.util.SSLRequestHelper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HTTPHelper;
import org.opensearch.threadpool.ThreadPool;

import org.opensearch.security.ssl.util.SSLRequestHelper.SSLInfo;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.user.User;
import org.greenrobot.eventbus.Subscribe;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class SecurityRestFilter {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final BackendRegistry registry;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    private final PrincipalExtractor principalExtractor;
    private final Settings settings;
    private final Path configPath;
    private final CompatConfig compatConfig;

    private WhitelistingSettings whitelistingSettings;

    private static final String HEALTH_SUFFIX = "health";
    private static final String REGEX_PATH_PREFIX = "/("+ LEGACY_OPENDISTRO_PREFIX + "|" + PLUGINS_PREFIX + ")/" +"(.*)";
    private static final Pattern PATTERN_PATH_PREFIX = Pattern.compile(REGEX_PATH_PREFIX);


    public SecurityRestFilter(final BackendRegistry registry, final AuditLog auditLog,
                              final ThreadPool threadPool, final PrincipalExtractor principalExtractor,
                              final Settings settings, final Path configPath, final CompatConfig compatConfig) {
        super();
        this.registry = registry;
        this.auditLog = auditLog;
        this.threadContext = threadPool.getThreadContext();
        this.principalExtractor = principalExtractor;
        this.settings = settings;
        this.configPath = configPath;
        this.compatConfig = compatConfig;
        this.whitelistingSettings = new WhitelistingSettings();
    }

    /**
     * This function wraps around all rest requests
     * If the request is authenticated, then it goes through a whitelisting check.
     * The whitelisting check works as follows:
     * If whitelisting is not enabled, then requests are handled normally.
     * If whitelisting is enabled, then SuperAdmin is allowed access to all APIs, regardless of what is currently whitelisted.
     * If whitelisting is enabled, then Non-SuperAdmin is allowed to access only those APIs that are whitelisted in {@link #requests}
     * For example: if whitelisting is enabled and requests = ["/_cat/nodes"], then SuperAdmin can access all APIs, but non SuperAdmin
     * can only access "/_cat/nodes"
     * Further note: Some APIs are only accessible by SuperAdmin, regardless of whitelisting. For example: /_opendistro/_security/api/whitelist is only accessible by SuperAdmin.
     * See {@link WhitelistApiAction} for the implementation of this API.
     * SuperAdmin is identified by credentials, which can be passed in the curl request.
     */
    public RestHandler wrap(RestHandler original, AdminDNs adminDNs) {
        return (request, channel, client) -> {
            org.apache.logging.log4j.ThreadContext.clearAll();
            final SecurityRequestChannel requestChannel = SecurityRequestFactory.from(request, channel);

            // Authenticate request
            checkAndAuthenticateRequest(requestChannel);
            if (requestChannel.getQueuedResponse().isPresent()) {
                requestChannel.sendResponse();
                return;
            }

            // Authorize Request
            final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            if (userIsSuperAdmin(user, adminDNs)) {
                // Super admins are always authorized
                original.handleRequest(request, channel, client);
                return;
            }

            final Optional<SecurityResponse> deniedResponse = whitelistingSettings.checkRequestIsAllowed(requestChannel);

            if (deniedResponse.isPresent()) {
                requestChannel.queueForSending(deniedResponse.orElseThrow());
                requestChannel.sendResponse();
                return;
            }

            // Caller was authorized, forward the request to the handler
            original.handleRequest(request, channel, client);
        };
    }

    /**
     * Checks if a given user is a SuperAdmin
     */
    private boolean userIsSuperAdmin(User user, AdminDNs adminDNs) {
        return user != null && adminDNs.isAdmin(user);
    }

    public void checkAndAuthenticateRequest(SecurityRequestChannel requestChannel) throws Exception {
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, Origin.REST.toString());

        if (HTTPHelper.containsBadHeader(requestChannel)) {
            final OpenSearchException exception = ExceptionUtils.createBadHeaderException();
            log.error(exception.toString());
            auditLog.logBadHeaders(requestChannel);

            requestChannel.queueForSending(new SecurityResponse(HttpStatus.SC_FORBIDDEN, null, exception.toString()));
            return;
        }
        
        if(SSLRequestHelper.containsBadHeader(threadContext, ConfigConstants.OPENDISTRO_SECURITY_CONFIG_PREFIX)) {
            final OpenSearchException exception = ExceptionUtils.createBadHeaderException();
            log.error(exception.toString());
            auditLog.logBadHeaders(requestChannel);

            requestChannel.queueForSending(new SecurityResponse(HttpStatus.SC_FORBIDDEN, null, exception.toString()));
            return;
        }

        final SSLInfo sslInfo;
        try {
            if ((sslInfo = SSLRequestHelper.getSSLInfo(settings, configPath, requestChannel, principalExtractor)) != null) {
                if (sslInfo.getPrincipal() != null) {
                    threadContext.putTransient("_opendistro_security_ssl_principal", sslInfo.getPrincipal());
                }
                
                if(sslInfo.getX509Certs() != null) {
                     threadContext.putTransient("_opendistro_security_ssl_peer_certificates", sslInfo.getX509Certs());
                }
                threadContext.putTransient("_opendistro_security_ssl_protocol", sslInfo.getProtocol());
                threadContext.putTransient("_opendistro_security_ssl_cipher", sslInfo.getCipher());
            }
        } catch (SSLPeerUnverifiedException e) {
            log.error("No ssl info", e);
            auditLog.logSSLException(requestChannel, e);
            requestChannel.queueForSending(new SecurityResponse(HttpStatus.SC_FORBIDDEN, null, null));
            return;
        }

        if (!compatConfig.restAuthEnabled()) {
            // Authentication is disabled
            return;
        }

        Matcher matcher = PATTERN_PATH_PREFIX.matcher(requestChannel.path());
        final String suffix = matcher.matches() ? matcher.group(2) : null;
        if (requestChannel.method() != Method.OPTIONS && !(HEALTH_SUFFIX.equals(suffix))) {
            if (!registry.authenticate(requestChannel)) {
                // another roundtrip
                org.apache.logging.log4j.ThreadContext.remove("user");
                return;
            } else {
                // make it possible to filter logs by username
                org.apache.logging.log4j.ThreadContext.put("user", ((User)threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER)).getName());
            }
        }
    }

    @Subscribe
    public void onWhitelistingSettingChanged(WhitelistingSettings whitelistingSettings) {
        this.whitelistingSettings = whitelistingSettings;
    }
}
