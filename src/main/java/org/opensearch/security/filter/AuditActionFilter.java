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

import org.opensearch.action.ActionRequest;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.IndicesRequest;
import org.opensearch.action.bulk.BulkItemRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkShardRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.collect.Tuple;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.xcontent.MediaType;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;

/**
 * A lightweight action filter that logs audit events without performing
 * authentication or authorization. Used in SSL-only and disabled modes
 * where the full SecurityFilter is not registered.
 *
 * Produces a single REQUEST_AUDIT event per request with:
 * source IP, action name, target indices, request type, node info,
 * task ID, client cert identity, request body, and filtered headers.
 */
public class AuditActionFilter implements ActionFilter {

    private static final Logger log = LogManager.getLogger(AuditActionFilter.class);

    private final AuditLog auditLog;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;
    private final AuditConfig.Filter filter;
    private final String auditIndexPrefix;

    public AuditActionFilter(
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
     * Run before authentication/authorization filters so audit captures the
     * original request even if a later filter rejects it. The existing
     * SecurityFilter uses Integer.MIN_VALUE; we use a less extreme value
     * to leave room for other "must run early" filters without colliding.
     */
    private static final int AUDIT_FILTER_ORDER = -200;

    @Override
    public int order() {
        return AUDIT_FILTER_ORDER;
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
        // Skip internal actions
        if (action != null && action.startsWith("internal:")) {
            chain.proceed(task, action, request, listener);
            return;
        }

        // Skip requests targeting the audit index (prevent self-referential loop)
        if (request instanceof IndicesRequest) {
            String[] indices = ((IndicesRequest) request).indices();
            if (indices != null) {
                for (String idx : indices) {
                    if (isAuditIndex(idx)) {
                        chain.proceed(task, action, request, listener);
                        return;
                    }
                }
            }
        }

        // Skip ignored users
        String principal = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL);
        User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        String effectiveUser = user != null ? user.getName() : principal;
        if (effectiveUser != null && filter.isAuditDisabled(effectiveUser)) {
            chain.proceed(task, action, request, listener);
            return;
        }

        // Skip ignored requests (matches action name or request class name)
        if (filter.isRequestAuditDisabled(action) || filter.isRequestAuditDisabled(request.getClass().getSimpleName())) {
            chain.proceed(task, action, request, listener);
            return;
        }

        // Short-circuit if REQUEST_AUDIT is disabled — avoid building AuditMessage,
        // resolving indices, and extracting body when the event would be discarded downstream.
        // Mirrors AuditTransportInterceptor's behavior and covers both bulk and non-bulk paths.
        if (filter.getDisabledCategories().contains(AuditCategory.REQUEST_AUDIT)
            || filter.getDisabledRestCategories().contains(AuditCategory.REQUEST_AUDIT)) {
            chain.proceed(task, action, request, listener);
            return;
        }

        // Bulk request handling — log each sub-operation separately.
        if (filter.shouldResolveBulkRequests() && (request instanceof BulkShardRequest || request instanceof BulkRequest)) {
            try {
                TransportAddress remoteAddress = request.remoteAddress();
                if (remoteAddress == null) {
                    remoteAddress = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
                }

                Map<String, List<String>> headers = threadPool.getThreadContext().getTransient(ConfigConstants.SECURITY_AUDIT_REST_HEADERS);
                Map<String, List<String>> filteredHeaders = AuditHeaderUtils.filterHeaders(headers, filter);

                if (request instanceof BulkShardRequest) {
                    BulkShardRequest bulkShardRequest = (BulkShardRequest) request;
                    for (BulkItemRequest item : bulkShardRequest.items()) {
                        logBulkItem(
                            item.request(),
                            action,
                            task,
                            effectiveUser,
                            remoteAddress,
                            filteredHeaders,
                            bulkShardRequest.shardId()
                        );
                    }
                } else {
                    BulkRequest bulkRequest = (BulkRequest) request;
                    for (DocWriteRequest<?> innerRequest : bulkRequest.requests()) {
                        logBulkItem(innerRequest, action, task, effectiveUser, remoteAddress, filteredHeaders, null);
                    }
                }
            } catch (Exception e) {
                log.error("Failed to log bulk audit events for action '{}': {}", action, e.getMessage(), e);
            }

            chain.proceed(task, action, request, listener);
            return;
        }

        try {
            AuditMessage msg = new AuditMessage(AuditCategory.REQUEST_AUDIT, clusterService, Origin.REST, Origin.TRANSPORT);

            // Source IP
            TransportAddress remoteAddress = request.remoteAddress();
            if (remoteAddress == null) {
                remoteAddress = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
            }
            msg.addRemoteAddress(remoteAddress);

            // Action name
            msg.addPrivilege(action);

            // Request type
            msg.addRequestType(request.getClass().getSimpleName());

            // Target indices
            if (request instanceof IndicesRequest) {
                String[] indices = ((IndicesRequest) request).indices();
                msg.addIndices(indices);

                // Resolve wildcards to actual index names using framework-resolved indices
                if (filter.shouldResolveIndices()) {
                    OptionallyResolvedIndices optionalResolved = actionRequestMetadata.resolvedIndices();
                    if (optionalResolved instanceof ResolvedIndices resolvedIndices) {
                        String[] resolved = resolvedIndices.local().namesOfIndices(clusterService.state()).toArray(String[]::new);
                        if (resolved.length > 0) {
                            msg.addResolvedIndices(resolved);
                        }
                    }
                }
            } else if (request instanceof BulkRequest) {
                // BulkRequest doesn't implement IndicesRequest, but we can still collect
                // the distinct target indices from its sub-items for visibility
                BulkRequest bulkRequest = (BulkRequest) request;
                String[] distinctIndices = bulkRequest.requests()
                    .stream()
                    .map(r -> r.index())
                    .filter(idx -> idx != null)
                    .distinct()
                    .toArray(String[]::new);
                if (distinctIndices.length > 0) {
                    msg.addIndices(distinctIndices);
                }
            }

            // Task ID
            if (task != null) {
                msg.addTaskId(task.getId());
                if (task.getParentTaskId() != null && task.getParentTaskId().isSet()) {
                    msg.addTaskParentId(task.getParentTaskId().toString());
                }
            }

            // Effective user — FGAC user takes priority over SSL principal
            if (user != null) {
                msg.addEffectiveUser(user.getName());
            } else if (principal != null) {
                msg.addEffectiveUser(principal);
            }

            // REST headers (stashed by REST wrapper, filtered here)
            Map<String, List<String>> headers = threadPool.getThreadContext().getTransient(ConfigConstants.SECURITY_AUDIT_REST_HEADERS);
            Map<String, List<String>> filteredHeaders = AuditHeaderUtils.filterHeaders(headers, filter);
            if (!filteredHeaders.isEmpty()) {
                msg.addRestHeaders(filteredHeaders, false, null);
            }

            // Request body (extracted from transport request object)
            if (filter.shouldLogRequestBody()) {
                addRequestBody(msg, request);
            }

            auditLog.logRequestAudit(msg);
        } catch (Exception e) {
            log.error("Failed to log audit event for action '{}': {}", action, e.getMessage(), e);
        }
        chain.proceed(task, action, request, listener);
    }

    private void logBulkItem(
        DocWriteRequest<?> innerRequest,
        String action,
        Task task,
        String effectiveUser,
        TransportAddress remoteAddress,
        Map<String, List<String>> filteredHeaders,
        ShardId shardId
    ) {
        // Skip items targeting the audit index (per-item self-loop guard for bulk)
        if (isAuditIndex(innerRequest.index())) {
            return;
        }

        AuditMessage msg = new AuditMessage(AuditCategory.REQUEST_AUDIT, clusterService, Origin.REST, Origin.TRANSPORT);

        msg.addRemoteAddress(remoteAddress);
        msg.addPrivilege(action);
        msg.addRequestType(innerRequest.getClass().getSimpleName());
        msg.addIndices(new String[] { innerRequest.index() });
        msg.addId(innerRequest.id());

        if (shardId != null) {
            msg.addShardId(shardId);
        }
        if (task != null) {
            msg.addTaskId(task.getId());
        }
        if (effectiveUser != null) {
            msg.addEffectiveUser(effectiveUser);
        }
        if (!filteredHeaders.isEmpty()) {
            msg.addRestHeaders(filteredHeaders, false, null);
        }
        if (filter.shouldLogRequestBody() && innerRequest instanceof IndexRequest) {
            IndexRequest ir = (IndexRequest) innerRequest;
            if (ir.source() != null) {
                msg.addTupleToRequestBody(new Tuple<>(ir.getContentType(), ir.source()));
            }
        }

        auditLog.logRequestAudit(msg);
    }

    private void addRequestBody(AuditMessage msg, ActionRequest request) {
        if (request instanceof SearchRequest) {
            SearchRequest sr = (SearchRequest) request;
            if (sr.source() != null) {
                msg.addMapToRequestBody(Utils.convertJsonToxToStructuredMap(sr.source()));
            }
        } else if (request instanceof IndexRequest) {
            IndexRequest ir = (IndexRequest) request;
            if (ir.source() != null) {
                msg.addTupleToRequestBody(new Tuple<MediaType, BytesReference>(ir.getContentType(), ir.source()));
            }
        } else if (request instanceof UpdateRequest) {
            UpdateRequest ur = (UpdateRequest) request;
            if (ur.doc() != null && ur.doc().source() != null) {
                msg.addTupleToRequestBody(new Tuple<MediaType, BytesReference>(ur.doc().getContentType(), ur.doc().source()));
            }
        }
    }
}
