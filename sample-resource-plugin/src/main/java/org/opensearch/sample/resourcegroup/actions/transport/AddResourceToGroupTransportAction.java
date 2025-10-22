/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.transport;

import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.sample.resourcegroup.actions.rest.add.AddResourceToGroupAction;
import org.opensearch.sample.resourcegroup.actions.rest.add.AddResourceToGroupRequest;
import org.opensearch.sample.resourcegroup.actions.rest.add.AddResourceToGroupResponse;
import org.opensearch.sample.utils.PluginClient;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for updating a resource.
 */
public class AddResourceToGroupTransportAction extends HandledTransportAction<AddResourceToGroupRequest, AddResourceToGroupResponse> {
    private static final Logger log = LogManager.getLogger(AddResourceToGroupTransportAction.class);

    private final TransportService transportService;
    private final PluginClient pluginClient;

    @Inject
    public AddResourceToGroupTransportAction(TransportService transportService, ActionFilters actionFilters, PluginClient pluginClient) {
        super(AddResourceToGroupAction.NAME, transportService, actionFilters, AddResourceToGroupRequest::new);
        this.transportService = transportService;
        this.pluginClient = pluginClient;
    }

    @Override
    protected void doExecute(Task task, AddResourceToGroupRequest request, ActionListener<AddResourceToGroupResponse> listener) {
        if (request.getResourceId() == null || request.getResourceId().isEmpty()) {
            listener.onFailure(new IllegalArgumentException("Resource Group ID cannot be null or empty"));
            return;
        }
        // Check permission to resource
        addResourceToGroup(request, listener);
    }

    private void addResourceToGroup(AddResourceToGroupRequest request, ActionListener<AddResourceToGroupResponse> listener) {
        try {
            String resourceId = request.getResourceId();
            String groupId = request.getGroupId();
            // because some plugins seem to treat update API calls as index request
            UpdateRequest ur = new UpdateRequest().index(RESOURCE_INDEX_NAME)
                .id(resourceId)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL) // WAIT_UNTIL because we don't want tests to fail, as they
                                                                         // execute search right after update
                .upsert(Map.of("parent_id", groupId));

            log.debug("Update Request: {}", ur.toString());

            pluginClient.update(ur, ActionListener.wrap(updateResponse -> {
                listener.onResponse(new AddResourceToGroupResponse("Resource ID " + resourceId + " added to group ID " + groupId + "."));
            }, listener::onFailure));
        } catch (Exception e) {
            log.error("Failed to update resource: {}", request.getResourceId(), e);
            listener.onFailure(e);
        }

    }
}
