/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.transport;

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
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.resourcegroup.actions.rest.delete.DeleteResourceGroupAction;
import org.opensearch.sample.resourcegroup.actions.rest.delete.DeleteResourceGroupRequest;
import org.opensearch.sample.resourcegroup.actions.rest.delete.DeleteResourceGroupResponse;
import org.opensearch.sample.utils.PluginClient;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for deleting a resource
 */
public class DeleteResourceGroupTransportAction extends HandledTransportAction<DeleteResourceGroupRequest, DeleteResourceGroupResponse> {
    private static final Logger log = LogManager.getLogger(DeleteResourceGroupTransportAction.class);

    private final TransportService transportService;
    private final PluginClient pluginClient;

    @Inject
    public DeleteResourceGroupTransportAction(TransportService transportService, ActionFilters actionFilters, PluginClient pluginClient) {
        super(DeleteResourceGroupAction.NAME, transportService, actionFilters, DeleteResourceGroupRequest::new);
        this.transportService = transportService;
        this.pluginClient = pluginClient;
    }

    @Override
    protected void doExecute(Task task, DeleteResourceGroupRequest request, ActionListener<DeleteResourceGroupResponse> listener) {
        String resourceId = request.getResourceId();
        if (resourceId == null || resourceId.isEmpty()) {
            listener.onFailure(new IllegalArgumentException("Resource group ID cannot be null or empty"));
            return;
        }
        ActionListener<DeleteResponse> deleteResponseListener = ActionListener.wrap(deleteResponse -> {
            if (deleteResponse.getResult() == DocWriteResponse.Result.NOT_FOUND) {
                listener.onFailure(new ResourceNotFoundException("Resource group " + resourceId + " not found."));
            } else {
                listener.onResponse(new DeleteResourceGroupResponse("Resource group " + resourceId + " deleted successfully."));
            }
        }, exception -> {
            log.error("Failed to delete resource group: " + resourceId, exception);
            listener.onFailure(exception);
        });

        deleteResource(resourceId, deleteResponseListener);
    }

    private void deleteResource(String resourceId, ActionListener<DeleteResponse> listener) {
        DeleteRequest deleteRequest = new DeleteRequest(RESOURCE_INDEX_NAME, resourceId).setRefreshPolicy(
            WriteRequest.RefreshPolicy.IMMEDIATE
        );

        pluginClient.delete(deleteRequest, listener);
    }

}
