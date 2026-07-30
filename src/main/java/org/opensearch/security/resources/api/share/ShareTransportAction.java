/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.api.share;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.resources.sharing.ResourceSharing;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

/**
 * Transport action for handling resource access requests.
 */
public class ShareTransportAction extends HandledTransportAction<ShareRequest, ShareResponse> {
    private final ResourceAccessHandler resourceAccessHandler;

    @Inject
    public ShareTransportAction(
        TransportService transportService,
        ActionFilters actionFilters,
        ResourceAccessHandler resourceAccessHandler
    ) {
        super(ShareAction.NAME, transportService, actionFilters, ShareRequest::new);
        this.resourceAccessHandler = resourceAccessHandler;
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
     * Wraps a listener to fire a RESOURCE_SHARING_CHANGED audit event after a successful mutation.
     * Uses GuiceHolder to access the AuditLog since it's registered by concrete class in Guice
     * and cannot be injected by interface type.
     */
    private ActionListener<ResourceSharing> auditingListener(
        ActionListener<ResourceSharing> delegate,
        ShareRequest request,
        Task task,
        String sharingAction
    ) {
        return ActionListener.wrap(resourceSharing -> {
            AuditLog auditLog = OpenSearchSecurityPlugin.GuiceHolder.getAuditLog();
            if (auditLog != null) {
                auditLog.logResourceSharingChanged(
                    request.id(),
                    request.type(),
                    sharingAction,
                    request.getAdd() != null ? request.getAdd().toString() : null,
                    request.getRevoke() != null ? request.getRevoke().toString() : null,
                    request.getShareWith() != null ? request.getShareWith().toString() : null,
                    task
                );
            }
            delegate.onResponse(resourceSharing);
        }, e -> {
            AuditLog auditLog = OpenSearchSecurityPlugin.GuiceHolder.getAuditLog();
            if (auditLog != null) {
                auditLog.logResourceSharingChanged(
                    request.id(),
                    request.type(),
                    sharingAction + "_denied",
                    request.getAdd() != null ? request.getAdd().toString() : null,
                    request.getRevoke() != null ? request.getRevoke().toString() : null,
                    request.getShareWith() != null ? request.getShareWith().toString() : null,
                    task
                );
            }
            delegate.onFailure(e);
        });
    }

}
