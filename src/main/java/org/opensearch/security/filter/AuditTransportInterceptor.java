/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.filter;

import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.IndicesRequest;
import org.opensearch.action.support.replication.TransportReplicationAction.ConcreteShardRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
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
    private final AuditConfig.Filter filter;
    private final String auditIndexPrefix;

    public AuditTransportInterceptor(
        AuditLog auditLog,
        ClusterService clusterService,
        ThreadPool threadPool,
        AuditConfig.Filter filter,
        String auditIndexPrefix
    ) {
        this.auditLog = auditLog;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.filter = filter;
        this.auditIndexPrefix = auditIndexPrefix;

        if (auditIndexPrefix == null || auditIndexPrefix.isEmpty()) {
            log.warn(
                "Audit index prefix is null or empty — self-loop guard is disabled. "
                    + "Verify 'plugins.security.audit.config.index' is configured correctly."
            );
        }
    }

    /**
     * Returns true if the given index name belongs to the audit index (i.e., writes
     * to it should not be audited to prevent self-referential loops).
     * Returns false if the prefix is null/empty to avoid silently suppressing all events.
     */
    private boolean isAuditIndex(String idx) {
        if (idx == null || auditIndexPrefix == null || auditIndexPrefix.isEmpty()) {
            return false;
        }
        return idx.startsWith(auditIndexPrefix);
    }

    /**
     * Unwraps a shard-level replication request so the audit index guard can see the real target.
     * {@link org.opensearch.action.support.replication.TransportReplicationAction} reroutes primary
     * and replica operations wrapped in {@link ConcreteShardRequest}, which extends
     * {@link TransportRequest} and does not implement {@link IndicesRequest} — so without unwrapping,
     * every {@code [p]}/{@code [r]}/{@code [s]} request looks index-less and the guard never matches.
     * That let writes to the audit index be audited, which produced more writes to it.
     * {@code ConcreteReplicaRequest} extends {@code ConcreteShardRequest}, so the loop covers both.
     */
    private static TransportRequest unwrapShardRequest(TransportRequest request) {
        TransportRequest current = request;
        while (current instanceof ConcreteShardRequest<?>) {
            current = ((ConcreteShardRequest<?>) current).getRequest();
        }
        return current;
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
                // Skip internal actions — cluster coordination traffic that should never be audited
                if (action != null && action.startsWith("internal:")) {
                    actualHandler.messageReceived(request, channel, task);
                    return;
                }

                // Skip if TRANSPORT_AUDIT is disabled
                if (!filter.getDisabledTransportCategories().contains(AuditCategory.TRANSPORT_AUDIT)
                    && !filter.getDisabledCategories().contains(AuditCategory.TRANSPORT_AUDIT)) {
                    // Skip ignored requests (action or class name). Match on the unwrapped request so an
                    // ignore_requests rule naming a request class still applies to shard-level replication.
                    final String requestTypeName = unwrapShardRequest(request).getClass().getSimpleName();
                    if (!filter.isRequestAuditDisabled(action) && !filter.isRequestAuditDisabled(requestTypeName)) {
                        // Skip ignored users
                        String principal = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL);
                        User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                        String effectiveUser = user != null ? user.getName() : principal;
                        if (effectiveUser == null || filter.isAuditEnabled(effectiveUser)) {
                            logTransportEvent(action, request, task);
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
            // The wrapper carries no indices and no meaningful type; everything about what is being
            // operated on lives on the request it wraps.
            final TransportRequest auditedRequest = unwrapShardRequest(request);

            // Skip requests targeting the audit index (prevent self-referential loop)
            if (auditedRequest instanceof IndicesRequest) {
                String[] indices = ((IndicesRequest) auditedRequest).indices();
                if (indices != null) {
                    for (String idx : indices) {
                        if (isAuditIndex(idx)) {
                            return;
                        }
                    }
                }
            }

            AuditMessage msg = new AuditMessage(AuditCategory.TRANSPORT_AUDIT, clusterService, Origin.TRANSPORT, Origin.TRANSPORT);

            // Action name
            msg.addPrivilege(action);

            // Request type
            msg.addRequestType(auditedRequest.getClass().getSimpleName());

            // Source IP — read from the request as received, since the transport layer sets this on
            // the outer wrapper rather than on the request it carries
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
            if (auditedRequest instanceof IndicesRequest) {
                String[] indices = ((IndicesRequest) auditedRequest).indices();
                if (indices != null && indices.length > 0) {
                    msg.addIndices(indices);
                }
            }

            // REST headers (stashed in ThreadContext by REST wrapper)
            Map<String, List<String>> headers = threadPool.getThreadContext().getTransient(ConfigConstants.SECURITY_AUDIT_REST_HEADERS);
            Map<String, List<String>> filteredHeaders = AuditHeaderUtils.filterHeaders(headers, filter);
            if (!filteredHeaders.isEmpty()) {
                msg.addRestHeaders(filteredHeaders, false, null);
            }

            auditLog.logTransportAudit(msg);
        } catch (Exception | AssertionError e) {
            log.warn("Failed to log transport audit event for action {}: {}", action, e.getMessage());
        }
    }
}
