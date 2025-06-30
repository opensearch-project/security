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

        if (request.getPatch() != null) {
            resourceAccessHandler.patchSharingInfo(
                request.getResourceId(),
                request.getResourceIndex(),
                request.getPatch(),
                ActionListener.wrap(resourceSharing -> listener.onResponse(new ShareResponse(resourceSharing)), listener::onFailure)
            );

        } else if (request.getShareWith() != null) {
            resourceAccessHandler.share(
                request.getResourceId(),
                request.getResourceIndex(),
                request.getShareWith(),
                ActionListener.wrap(response -> listener.onResponse(new ShareResponse(response)), listener::onFailure)
            );
        }

    }

}
