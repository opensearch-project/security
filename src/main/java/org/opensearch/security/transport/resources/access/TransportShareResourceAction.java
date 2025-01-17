/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.transport.resources.access;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.rest.resources.access.share.ShareResourceAction;
import org.opensearch.security.rest.resources.access.share.ShareResourceRequest;
import org.opensearch.security.rest.resources.access.share.ShareResourceResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportShareResourceAction extends HandledTransportAction<ShareResourceRequest, ShareResourceResponse> {
    private static final Logger log = LogManager.getLogger(TransportShareResourceAction.class);
    private final ResourceAccessHandler resourceAccessHandler;

    @Inject
    public TransportShareResourceAction(
        TransportService transportService,
        ActionFilters actionFilters,
        ResourceAccessHandler resourceAccessHandler
    ) {
        super(ShareResourceAction.NAME, transportService, actionFilters, ShareResourceRequest::new);
        this.resourceAccessHandler = resourceAccessHandler;
    }

    @Override
    protected void doExecute(Task task, ShareResourceRequest request, ActionListener<ShareResourceResponse> listener) {
        try {
            this.resourceAccessHandler.shareWith(
                request.getResourceId(),
                request.getResourceIndex(),
                request.getShareWith(),
                ActionListener.wrap(resourceSharing -> {
                    if (resourceSharing == null) {
                        log.error("Failed to share resource {}", request.getResourceId());
                        listener.onFailure(new OpenSearchException("Failed to share resource " + request.getResourceId()));
                    } else {
                        log.info("Shared resource : {} with {}", request.getResourceId(), resourceSharing.toString());
                        listener.onResponse(new ShareResourceResponse("Resource " + request.getResourceId() + " shared successfully."));
                    }
                }, e -> {
                    log.error("Error while sharing resource {}: {}", request.getResourceId(), e.getMessage(), e);
                    listener.onFailure(e);
                })
            );
        } catch (Exception e) {
            log.error("Exception while trying to share resource {}: {}", request.getResourceId(), e.getMessage(), e);
            listener.onFailure(e);
        }
    }
}
