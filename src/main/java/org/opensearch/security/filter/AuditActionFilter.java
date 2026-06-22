/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.filter;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.IndicesRequest;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.tasks.Task;

/**
 * A lightweight action filter that logs audit events without performing
 * authentication or authorization. Used in SSL-only and disabled modes
 * where the full SecurityFilter is not registered.
 *
 * Builds REQUEST_AUDIT events directly with the data available in non-FGAC modes:
 * source IP, action name, target indices, request type, node info, timestamp.
 */
public class AuditActionFilter implements ActionFilter {

    private final AuditLog auditLog;
    private final ClusterService clusterService;

    public AuditActionFilter(AuditLog auditLog, ClusterService clusterService) {
        this.auditLog = auditLog;
        this.clusterService = clusterService;
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE;
    }

    @Override
    public <Request extends ActionRequest, Response extends ActionResponse> void apply(
        Task task,
        String action,
        Request request,
        ActionRequestMetadata<Request, Response> actionRequestMetadata,
        ActionListener<Response> listener,
        ActionFilterChain<Request, Response> chain
    ) {
        // Build the audit event with fields available in non-FGAC modes
        AuditMessage msg = new AuditMessage(AuditCategory.REQUEST_AUDIT, clusterService, Origin.REST, Origin.TRANSPORT);

        // Source IP — from the request directly 
        TransportAddress remoteAddress = request.remoteAddress();
        msg.addRemoteAddress(remoteAddress);

        // Action name — the transport action string (e.g., "indices:data/write/index")
        msg.addPrivilege(action);

        // Request type — the class name (e.g., "IndexRequest", "SearchRequest")
        msg.addRequestType(request.getClass().getSimpleName());

        // Target indices — if the request is index-scoped
        if (request instanceof IndicesRequest) {
            msg.addIndices(((IndicesRequest) request).indices());
        }

        // Task ID — for correlating related operations
        if (task != null) {
            msg.addTaskId(task.getId());
            if (task.getParentTaskId() != null && task.getParentTaskId().isSet()) {
                msg.addTaskParentId(task.getParentTaskId().toString());
            }
        }

        // TODO: request body (Phase 2 — needs configurable sensitive header exclusion)
        // TODO: user identity from client cert CN/SAN in SSL-only mode

        auditLog.logRequestAudit(msg); // routes to configured sink (log4j, index, etc)
        chain.proceed(task, action, request, listener); //  passes the request to the next filter in the chain, or if there are no more filters, executes the actual action (index the doc, run the search, etc.).
    }
}
