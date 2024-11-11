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
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.sample.actions.share.ShareResourceAction;
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

    @Inject
    public ShareResourceTransportAction(TransportService transportService, ActionFilters actionFilters) {
        super(ShareResourceAction.NAME, transportService, actionFilters, ShareResourceRequest::new);
    }

    @Override
    protected void doExecute(Task task, ShareResourceRequest request, ActionListener<ShareResourceResponse> listener) {
        try {
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
