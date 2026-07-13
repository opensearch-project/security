/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.filter;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.IndicesRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportChannel;
import org.opensearch.transport.TransportInterceptor;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestHandler;

/**
 * A transport-layer interceptor that logs audit events for inter-node
 * communication. Captures incoming transport requests on the receiving node.
 * Works in all security modes (FGAC, SSL-only, disabled).
 *
 * Only intercepts the handler side (incoming requests) to avoid double-logging
 * the same operation on both sender and receiver.
 */
public class AuditTransportInterceptor implements TransportInterceptor {

    private static final Logger log = LogManager.getLogger(AuditTransportInterceptor.class);

    private final AuditLog auditLog;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;
    private final WildcardMatcher ignoreActionsMatcher;
    private final WildcardMatcher ignoreUsersMatcher;
    private final WildcardMatcher ignoreRequestsMatcher;
    private final Set<AuditCategory> disabledCategories;

    public AuditTransportInterceptor(AuditLog auditLog, ClusterService clusterService, ThreadPool threadPool, Settings settings) {
        this.auditLog = auditLog;
        this.clusterService = clusterService;
        this.threadPool = threadPool;

        // Skip internal cluster noise by default
        this.ignoreActionsMatcher = WildcardMatcher.from(
            "internal:*",
            "cluster:monitor/*",
            "indices:monitor/*"
        );

        // Respect same ignore settings as AuditActionFilter
        List<String> ignoreUsers = settings.getAsList(
            ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS,
            List.of()
        );
        this.ignoreUsersMatcher = WildcardMatcher.from(ignoreUsers);

        List<String> ignoreRequests = settings.getAsList(
            ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS,
            List.of()
        );
        this.ignoreRequestsMatcher = WildcardMatcher.from(ignoreRequests);

        // Respect disabled transport categories (check unified setting first, then transport-specific)
        List<String> unifiedDisabledCats = settings.getAsList(
            ConfigConstants.SECURITY_AUDIT_CONFIG_DISABLED_CATEGORIES,
            List.of()
        );
        List<String> disabledCats;
        if (!unifiedDisabledCats.isEmpty()) {
            disabledCats = unifiedDisabledCats;
        } else {
            disabledCats = settings.getAsList(
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_TRANSPORT_CATEGORIES_DEFAULT
            );
        }
        this.disabledCategories = disabledCats.stream()
            .map(s -> {
                try { return AuditCategory.valueOf(s.toUpperCase()); }
                catch (Exception e) { return null; }
            })
            .filter(c -> c != null)
            .collect(Collectors.toSet());
    }

    @Override
    public <T extends TransportRequest> TransportRequestHandler<T> interceptHandler(
        String action,
        String executor,
        boolean forceExecution,
        TransportRequestHandler<T> actualHandler
    ) {
        return new TransportRequestHandler<T>() {
            @Override
            public void messageReceived(T request, TransportChannel channel, Task task) throws Exception {
                // Skip noisy internal actions
                if (!ignoreActionsMatcher.test(action)) {
                    // Skip if TRANSPORT_AUDIT is disabled
                    if (!disabledCategories.contains(AuditCategory.TRANSPORT_AUDIT)) {
                        // Skip ignored requests (action or class name)
                        if (!ignoreRequestsMatcher.test(action)
                            && !ignoreRequestsMatcher.test(request.getClass().getSimpleName())) {
                            // Skip ignored users
                            String principal = threadPool.getThreadContext()
                                .getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL);
                            User user = threadPool.getThreadContext()
                                .getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                            String effectiveUser = user != null ? user.getName() : principal;
                            if (effectiveUser == null || !ignoreUsersMatcher.test(effectiveUser)) {
                                logTransportEvent(action, request, task);
                            }
                        }
                    }
                }
                // Always proceed — audit is non-blocking
                actualHandler.messageReceived(request, channel, task);
            }
        };
    }

    private <T extends TransportRequest> void logTransportEvent(String action, T request, Task task) {
        try {
            // Skip requests targeting the audit index (prevent self-referential loop)
            if (request instanceof IndicesRequest) {
                String[] indices = ((IndicesRequest) request).indices();
                if (indices != null) {
                    for (String idx : indices) {
                        if (idx != null && idx.startsWith("security-auditlog")) {
                            return;
                        }
                    }
                }
            }

            AuditMessage msg = new AuditMessage(AuditCategory.TRANSPORT_AUDIT, clusterService, Origin.TRANSPORT, Origin.TRANSPORT);

            // Action name
            msg.addPrivilege(action);

            // Request type
            msg.addRequestType(request.getClass().getSimpleName());

            // Source IP
            TransportAddress remoteAddress = request.remoteAddress();
            if (remoteAddress == null) {
                remoteAddress = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
            }
            msg.addRemoteAddress(remoteAddress);

            // Task ID
            if (task != null) {
                msg.addTaskId(task.getId());
                if (task.getParentTaskId() != null && task.getParentTaskId().isSet()) {
                    msg.addTaskParentId(task.getParentTaskId().toString());
                }
            }

            // User identity (from ThreadContext — available in FGAC, cert principal in SSL-only)
            String principal = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL);
            User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            if (user != null) {
                msg.addEffectiveUser(user.getName());
            } else if (principal != null) {
                msg.addEffectiveUser(principal);
            }

            // Indices (already concrete at transport layer — no wildcard resolution needed)
            if (request instanceof IndicesRequest) {
                String[] indices = ((IndicesRequest) request).indices();
                if (indices != null && indices.length > 0) {
                    msg.addIndices(indices);
                }
            }

            // REST headers (stashed in ThreadContext by REST wrapper)
            Map<String, List<String>> headers = threadPool.getThreadContext().getTransient(ConfigConstants.SECURITY_AUDIT_REST_HEADERS);
            if (headers != null && !headers.isEmpty()) {
                Map<String, List<String>> filteredHeaders = new HashMap<>(headers);
                filteredHeaders.keySet().removeIf(k -> k.equalsIgnoreCase("authorization"));
                msg.addRestHeaders(filteredHeaders, false, null);
            }

            auditLog.logTransportAudit(msg);
        } catch (Exception e) {
            log.warn("Failed to log transport audit event for action {}: {}", action, e.getMessage());
        }
    }
}
