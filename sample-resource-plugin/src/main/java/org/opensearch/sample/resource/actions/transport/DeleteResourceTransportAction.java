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

import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.resource.actions.rest.delete.DeleteResourceAction;
import org.opensearch.sample.resource.actions.rest.delete.DeleteResourceRequest;
import org.opensearch.sample.resource.actions.rest.delete.DeleteResourceResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for deleting a resource
 */
public class DeleteResourceTransportAction extends HandledTransportAction<DeleteResourceRequest, DeleteResourceResponse> {
    private static final Logger log = LogManager.getLogger(DeleteResourceTransportAction.class);

    private final TransportService transportService;
    private final NodeClient nodeClient;

    @Inject
    public DeleteResourceTransportAction(TransportService transportService, ActionFilters actionFilters, NodeClient nodeClient) {
        super(DeleteResourceAction.NAME, transportService, actionFilters, DeleteResourceRequest::new);
        this.transportService = transportService;
        this.nodeClient = nodeClient;
    }

    @Override
    protected void doExecute(Task task, DeleteResourceRequest request, ActionListener<DeleteResourceResponse> listener) {
        String resourceId = request.getResourceId();
        if (resourceId == null || resourceId.isEmpty()) {
            listener.onFailure(new IllegalArgumentException("Resource ID cannot be null or empty"));
            return;
        }
        ActionListener<DeleteResponse> deleteResponseListener = ActionListener.wrap(deleteResponse -> {
            if (deleteResponse.getResult() == DocWriteResponse.Result.NOT_FOUND) {
                listener.onFailure(new ResourceNotFoundException("Resource " + resourceId + " not found."));
            } else {
                listener.onResponse(new DeleteResourceResponse("Resource " + resourceId + " deleted successfully."));
            }
        }, exception -> {
            log.error("Failed to delete resource: " + resourceId, exception);
            listener.onFailure(exception);
        });

        ThreadContext threadContext = transportService.getThreadPool().getThreadContext();
        try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
            deleteResource(resourceId, deleteResponseListener);
        }
    }

    private void deleteResource(String resourceId, ActionListener<DeleteResponse> listener) {
        DeleteRequest deleteRequest = new DeleteRequest(RESOURCE_INDEX_NAME, resourceId).setRefreshPolicy(
            WriteRequest.RefreshPolicy.IMMEDIATE
        );

        nodeClient.delete(deleteRequest, listener);
    }

}
