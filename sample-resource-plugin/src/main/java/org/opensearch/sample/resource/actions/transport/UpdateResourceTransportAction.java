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

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.sample.SampleResource;
import org.opensearch.sample.resource.actions.rest.create.CreateResourceResponse;
import org.opensearch.sample.resource.actions.rest.create.UpdateResourceAction;
import org.opensearch.sample.resource.actions.rest.create.UpdateResourceRequest;
import org.opensearch.sample.utils.PluginClient;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for updating a resource.
 */
public class UpdateResourceTransportAction extends HandledTransportAction<UpdateResourceRequest, CreateResourceResponse> {
    private static final Logger log = LogManager.getLogger(UpdateResourceTransportAction.class);

    private final TransportService transportService;
    private final PluginClient pluginClient;

    @Inject
    public UpdateResourceTransportAction(TransportService transportService, ActionFilters actionFilters, PluginClient pluginClient) {
        super(UpdateResourceAction.NAME, transportService, actionFilters, UpdateResourceRequest::new);
        this.transportService = transportService;
        this.pluginClient = pluginClient;
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
        try {
            String resourceId = request.getResourceId();
            SampleResource sample = request.getResource();
            try (XContentBuilder builder = jsonBuilder()) {
                UpdateRequest ur = new UpdateRequest(RESOURCE_INDEX_NAME, resourceId).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .doc(sample.toXContent(builder, ToXContent.EMPTY_PARAMS));

                log.debug("Update Request: {}", ur.toString());

                pluginClient.update(ur, ActionListener.wrap(updateResponse -> {
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
