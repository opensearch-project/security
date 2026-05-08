/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.transport;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.DocRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.sample.SampleResourceGroup;
import org.opensearch.sample.resourcegroup.actions.rest.create.UpdateResourceGroupAction;
import org.opensearch.sample.utils.PluginClient;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;
import static org.opensearch.sample.utils.Constants.RESOURCE_GROUP_TYPE;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for updating a resource group.
 */
public class UpdateResourceGroupTransportAction extends HandledTransportAction<UpdateResourceGroupTransportAction.Request, CreateResourceGroupTransportAction.Response> {
    private static final Logger log = LogManager.getLogger(UpdateResourceGroupTransportAction.class);

    private final TransportService transportService;
    private final PluginClient pluginClient;

    @Inject
    public UpdateResourceGroupTransportAction(TransportService transportService, ActionFilters actionFilters, PluginClient pluginClient) {
        super(UpdateResourceGroupAction.NAME, transportService, actionFilters, Request::new);
        this.transportService = transportService;
        this.pluginClient = pluginClient;
    }

    @Override
    protected void doExecute(Task task, Request request, ActionListener<CreateResourceGroupTransportAction.Response> listener) {
        if (request.getResourceId() == null || request.getResourceId().isEmpty()) {
            listener.onFailure(new IllegalArgumentException("Resource Group ID cannot be null or empty"));
            return;
        }
        updateResource(request, listener);
    }

    private void updateResource(Request request, ActionListener<CreateResourceGroupTransportAction.Response> listener) {
        try {
            String resourceId = request.getResourceId();
            SampleResourceGroup sample = request.getResourceGroup();
            try (XContentBuilder builder = jsonBuilder()) {
                sample.toXContent(builder, ToXContent.EMPTY_PARAMS);

                IndexRequest ir = new IndexRequest(RESOURCE_INDEX_NAME).id(resourceId)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL)
                    .source(builder);

                log.debug("Update Request: {}", ir.toString());

                pluginClient.index(ir, ActionListener.wrap(updateResponse -> {
                    listener.onResponse(
                        new CreateResourceGroupTransportAction.Response("Resource " + request.getResourceGroup().getName() + " updated successfully.")
                    );
                }, listener::onFailure));
            }
        } catch (Exception e) {
            log.error("Failed to update resource: {}", request.getResourceId(), e);
            listener.onFailure(e);
        }
    }

    /**
     * Request object for UpdateResourceGroup transport action
     */
    public static class Request extends ActionRequest implements DocRequest {

        private final String resourceId;
        private final SampleResourceGroup resourceGroup;

        public Request(String resourceId, SampleResourceGroup resourceGroup) {
            this.resourceId = resourceId;
            this.resourceGroup = resourceGroup;
        }

        public Request(StreamInput in) throws IOException {
            this.resourceId = in.readString();
            this.resourceGroup = in.readNamedWriteable(SampleResourceGroup.class);
        }

        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            out.writeString(resourceId);
            resourceGroup.writeTo(out);
        }

        @Override
        public ActionRequestValidationException validate() {
            return null;
        }

        public SampleResourceGroup getResourceGroup() {
            return this.resourceGroup;
        }

        public String getResourceId() {
            return this.resourceId;
        }

        @Override
        public String type() {
            return RESOURCE_GROUP_TYPE;
        }

        @Override
        public String index() {
            return RESOURCE_INDEX_NAME;
        }

        @Override
        public String id() {
            return resourceId;
        }
    }
}
