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
                resourceAccessHandler.patchSharingInfo(
                    request.id(),
                    request.type(),
                    request.getAdd(),
                    request.getRevoke(),
                    sharingInfoListener
                );
                break;
            case PUT:
                resourceAccessHandler.share(request.id(), request.type(), request.getShareWith(), sharingInfoListener);
                break;
        }

    }

}
