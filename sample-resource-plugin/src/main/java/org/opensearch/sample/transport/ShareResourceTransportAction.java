/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.transport;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.accesscontrol.resources.ResourceService;
import org.opensearch.accesscontrol.resources.ResourceSharing;
import org.opensearch.accesscontrol.resources.ShareWith;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.sample.actions.share.ShareResourceRequest;
import org.opensearch.sample.actions.share.ShareResourceResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.SampleResourcePlugin.RESOURCE_INDEX_NAME;

/**
 * Transport action for CreateSampleResource.
 */
public class ShareResourceTransportAction extends HandledTransportAction<ShareResourceRequest, ShareResourceResponse> {
    private static final Logger log = LogManager.getLogger(ShareResourceTransportAction.class);

    private final TransportService transportService;
    private final Client nodeClient;
    private final String resourceIndex;

    @Inject
    public ShareResourceTransportAction(
        TransportService transportService,
        ActionFilters actionFilters,
        Client nodeClient,
        String actionName,
        String resourceIndex
    ) {
        super(actionName, transportService, actionFilters, ShareResourceRequest::new);
        this.transportService = transportService;
        this.nodeClient = nodeClient;
        this.resourceIndex = resourceIndex;
    }

    @Override
    protected void doExecute(Task task, ShareResourceRequest request, ActionListener<ShareResourceResponse> listener) {
        try (ThreadContext.StoredContext ignore = transportService.getThreadPool().getThreadContext().stashContext()) {
            shareResource(request);
            listener.onResponse(new ShareResourceResponse("Resource " + request.getResourceId() + " shared successfully."));
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    private void shareResource(ShareResourceRequest request) {
        try {
            ShareWith shareWith = new ShareWith(List.of());
            ResourceService rs = SampleResourcePlugin.GuiceHolder.getResourceService();
            ResourceSharing sharing = rs.getResourceAccessControlPlugin()
                .shareWith(request.getResourceId(), RESOURCE_INDEX_NAME, shareWith);
            log.info("Shared resource : {} with {}", request.getResourceId(), sharing.toString());
        } catch (Exception e) {
            log.info("Failed to share resource {}", request.getResourceId(), e);
            throw e;
        }
    }
}
