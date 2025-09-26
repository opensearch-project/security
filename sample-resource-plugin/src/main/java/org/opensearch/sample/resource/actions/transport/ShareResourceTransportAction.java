/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.sample.client.ResourceSharingClientAccessor;
import org.opensearch.sample.resource.actions.rest.share.ShareResourceAction;
import org.opensearch.sample.resource.actions.rest.share.ShareResourceRequest;
import org.opensearch.sample.resource.actions.rest.share.ShareResourceResponse;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;
import org.opensearch.security.spi.resources.sharing.ShareWith;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;

/**
 * Transport action implementation for sharing a resource.
 */
public class ShareResourceTransportAction extends HandledTransportAction<ShareResourceRequest, ShareResourceResponse> {
    private static final Logger log = LogManager.getLogger(ShareResourceTransportAction.class);
    private final ResourceSharingClient resourceSharingClient;

    @Inject
    public ShareResourceTransportAction(TransportService transportService, ActionFilters actionFilters) {
        super(ShareResourceAction.NAME, transportService, actionFilters, ShareResourceRequest::new);
        this.resourceSharingClient = ResourceSharingClientAccessor.getInstance().getResourceSharingClient();
    }

    @Override
    protected void doExecute(Task task, ShareResourceRequest request, ActionListener<ShareResourceResponse> listener) {
        if (request.getResourceId() == null || request.getResourceId().isEmpty()) {
            listener.onFailure(new IllegalArgumentException("Resource ID cannot be null or empty"));
            return;
        }

        if (resourceSharingClient == null) {
            listener.onFailure(
                new OpenSearchStatusException(
                    "Resource sharing is not enabled. Cannot share resource " + request.getResourceId(),
                    RestStatus.NOT_IMPLEMENTED
                )
            );
            return;
        }
        ShareWith shareWith = request.getShareWith();
        resourceSharingClient.share(request.getResourceId(), RESOURCE_TYPE, shareWith, ActionListener.wrap(sharing -> {
            ShareWith finalShareWith = sharing == null ? null : sharing.getShareWith();
            ShareResourceResponse response = new ShareResourceResponse(finalShareWith);
            log.debug("Shared resource: {}", response.toString());
            listener.onResponse(response);
        }, listener::onFailure));
    }

}
