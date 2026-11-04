/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.api.share;

import java.util.function.Supplier;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.ContextPreservingActionListener;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.impl.AuditLogImpl;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.resources.sharing.ResourceSharing;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

/**
 * Transport action for handling resource access requests.
 */
public class ShareTransportAction extends HandledTransportAction<ShareRequest, ShareResponse> {
    private final ResourceAccessHandler resourceAccessHandler;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;

    @Inject
    public ShareTransportAction(
        TransportService transportService,
        ActionFilters actionFilters,
        ResourceAccessHandler resourceAccessHandler,
        AuditLogImpl auditLog
    ) {
        super(ShareAction.NAME, transportService, actionFilters, ShareRequest::new);
        this.resourceAccessHandler = resourceAccessHandler;
        this.auditLog = auditLog;
        this.threadContext = transportService.getThreadPool().getThreadContext();
    }

    @Override
    protected void doExecute(Task task, ShareRequest request, ActionListener<ShareResponse> listener) {

        ActionListener<ResourceSharing> sharingInfoListener = ActionListener.wrap(
            resourceSharing -> listener.onResponse(new ShareResponse(resourceSharing)),
            listener::onFailure
        );
        switch (request.getMethod()) {
            case GET:
                resourceAccessHandler.getSharingInfo(request.id(), request.type(), sharingInfoListener);
                return;
            case PATCH:
            case POST:
                resourceAccessHandler.patchSharingInfo(
                    request.id(),
                    request.type(),
                    request.getAdd(),
                    request.getRevoke(),
                    request.isGeneralAccessPresent(),
                    request.getGeneralAccess(),
                    auditingListener(sharingInfoListener, request, task, "patch")
                );
                break;
            case PUT:
                resourceAccessHandler.share(
                    request.id(),
                    request.type(),
                    request.getShareWith(),
                    auditingListener(sharingInfoListener, request, task, "share")
                );
                break;
        }

    }

    /**
     * Wraps a listener to fire a RESOURCE_SHARING_CHANGED audit event after a successful mutation,
     * or a RESOURCE_SHARING_CHANGED event with result "failed" when the mutation fails after
     * authorization.
     *
     * Uses ContextPreservingActionListener to ensure the security user ThreadContext transients
     * (set at doExecute time) are available when the async callback fires, even if the callback
     * runs on a different threadpool thread after stashContext in ResourceSharingIndexHandler.
     */
    private ActionListener<ResourceSharing> auditingListener(
        ActionListener<ResourceSharing> delegate,
        ShareRequest request,
        Task task,
        String sharingAction
    ) {
        // Capture the current thread context (including security user) before async operations
        Supplier<ThreadContext.StoredContext> contextSupplier = threadContext.newRestorableContext(true);

        ActionListener<ResourceSharing> auditListener = ActionListener.wrap(resourceSharing -> {
            logSharingAudit(request, task, sharingAction, "success");
            delegate.onResponse(resourceSharing);
        }, e -> {
            logSharingAudit(request, task, sharingAction, "failed");
            delegate.onFailure(e);
        });

        return new ContextPreservingActionListener<>(contextSupplier, auditListener);
    }

    private void logSharingAudit(ShareRequest request, Task task, String sharingAction, String result) {
        auditLog.logResourceSharingChanged(
            request.id(),
            request.type(),
            sharingAction,
            result,
            request.getAdd() != null ? request.getAdd().toString() : null,
            request.getRevoke() != null ? request.getRevoke().toString() : null,
            request.getShareWith() != null ? request.getShareWith().toString() : null,
            request,
            task
        );
    }

}
