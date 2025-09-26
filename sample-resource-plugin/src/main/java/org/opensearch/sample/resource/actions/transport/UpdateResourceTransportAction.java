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

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.sample.SampleResource;
import org.opensearch.sample.resource.actions.rest.create.CreateResourceResponse;
import org.opensearch.sample.resource.actions.rest.create.UpdateResourceAction;
import org.opensearch.sample.resource.actions.rest.create.UpdateResourceRequest;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for updating a resource.
 */
public class UpdateResourceTransportAction extends HandledTransportAction<UpdateResourceRequest, CreateResourceResponse> {
    private static final Logger log = LogManager.getLogger(UpdateResourceTransportAction.class);

    private final TransportService transportService;
    private final NodeClient nodeClient;

    @Inject
    public UpdateResourceTransportAction(TransportService transportService, ActionFilters actionFilters, NodeClient nodeClient) {
        super(UpdateResourceAction.NAME, transportService, actionFilters, UpdateResourceRequest::new);
        this.transportService = transportService;
        this.nodeClient = nodeClient;
    }

    @Override
    protected void doExecute(Task task, UpdateResourceRequest request, ActionListener<CreateResourceResponse> listener) {
        if (request.getResourceId() == null || request.getResourceId().isEmpty()) {
            listener.onFailure(new IllegalArgumentException("Resource ID cannot be null or empty"));
            return;
        }
        // Check permission to resource
        updateResource(request, listener);
    }

    private void updateResource(UpdateResourceRequest request, ActionListener<CreateResourceResponse> listener) {
        ThreadContext threadContext = this.transportService.getThreadPool().getThreadContext();
        try (ThreadContext.StoredContext ignore = threadContext.stashContext()) {
            String resourceId = request.getResourceId();
            SampleResource sample = request.getResource();
            try (XContentBuilder builder = jsonBuilder()) {
                sample.toXContent(builder, ToXContent.EMPTY_PARAMS);

                // because some plugins seem to treat update API calls as index request
                IndexRequest ir = new IndexRequest(RESOURCE_INDEX_NAME).id(resourceId)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL) // WAIT_UNTIL because we don't want tests to fail, as they
                                                                             // execute search right after update
                    .source(builder);

                log.debug("Update Request: {}", ir.toString());

                nodeClient.index(ir, ActionListener.wrap(updateResponse -> {
                    listener.onResponse(
                        new CreateResourceResponse("Resource " + request.getResource().getName() + " updated successfully.")
                    );
                }, listener::onFailure));
            }
        } catch (Exception e) {
            log.error("Failed to update resource: {}", request.getResourceId(), e);
            listener.onFailure(e);
        }

    }
}
