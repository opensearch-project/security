/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.transport;

import java.io.IOException;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.accesscontrol.resources.ResourceService;
import org.opensearch.accesscontrol.resources.ResourceSharing;
import org.opensearch.accesscontrol.resources.ShareWith;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.sample.Resource;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.sample.actions.create.CreateResourceRequest;
import org.opensearch.sample.actions.create.CreateResourceResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;

/**
 * Transport action for CreateSampleResource.
 */
public class CreateResourceTransportAction extends HandledTransportAction<CreateResourceRequest, CreateResourceResponse> {
    private static final Logger log = LogManager.getLogger(CreateResourceTransportAction.class);

    private final TransportService transportService;
    private final Client nodeClient;
    private final String resourceIndex;

    @Inject
    public CreateResourceTransportAction(
        TransportService transportService,
        ActionFilters actionFilters,
        Client nodeClient,
        String actionName,
        String resourceIndex
    ) {
        super(actionName, transportService, actionFilters, (in) -> new CreateResourceRequest(in));
        this.transportService = transportService;
        this.nodeClient = nodeClient;
        this.resourceIndex = resourceIndex;
    }

    @Override
    protected void doExecute(Task task, CreateResourceRequest request, ActionListener<CreateResourceResponse> listener) {
        try (ThreadContext.StoredContext ignore = transportService.getThreadPool().getThreadContext().stashContext()) {
            createResource(request, listener);
            listener.onResponse(new CreateResourceResponse("Resource " + request.getResource() + " created successfully."));
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    private void createResource(CreateResourceRequest request, ActionListener<CreateResourceResponse> listener) {
        Resource sample = request.getResource();
        try {
            IndexRequest ir = nodeClient.prepareIndex(resourceIndex)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .setSource(sample.toXContent(jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .request();

            log.warn("Index Request: {}", ir.toString());

            ActionListener<IndexResponse> irListener = getIndexResponseActionListener(listener);
            nodeClient.index(ir, irListener);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static ActionListener<IndexResponse> getIndexResponseActionListener(ActionListener<CreateResourceResponse> listener) {
        ShareWith shareWith = new ShareWith(List.of());
        return ActionListener.wrap(idxResponse -> {
            log.info("Created resource: {}", idxResponse.toString());
            ResourceService rs = SampleResourcePlugin.GuiceHolder.getResourceService();
            ResourceSharing sharing = rs.getResourceAccessControlPlugin().shareWith(idxResponse.getId(), idxResponse.getIndex(), shareWith);
            log.info("Created resource sharing entry: {}", sharing.toString());
        }, listener::onFailure);
    }

}
