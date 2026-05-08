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

import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.DocRequest;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.sample.resourcegroup.actions.rest.delete.DeleteResourceGroupAction;
import org.opensearch.sample.utils.PluginClient;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.utils.Constants.RESOURCE_GROUP_TYPE;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for deleting a resource group
 */
public class DeleteResourceGroupTransportAction extends HandledTransportAction<DeleteResourceGroupTransportAction.Request, DeleteResourceGroupTransportAction.Response> {
    private static final Logger log = LogManager.getLogger(DeleteResourceGroupTransportAction.class);

    private final TransportService transportService;
    private final PluginClient pluginClient;

    @Inject
    public DeleteResourceGroupTransportAction(TransportService transportService, ActionFilters actionFilters, PluginClient pluginClient) {
        super(DeleteResourceGroupAction.NAME, transportService, actionFilters, Request::new);
        this.transportService = transportService;
        this.pluginClient = pluginClient;
    }

    @Override
    protected void doExecute(Task task, Request request, ActionListener<Response> listener) {
        String resourceId = request.getResourceId();
        if (resourceId == null || resourceId.isEmpty()) {
            listener.onFailure(new IllegalArgumentException("Resource group ID cannot be null or empty"));
            return;
        }
        ActionListener<DeleteResponse> deleteResponseListener = ActionListener.wrap(deleteResponse -> {
            if (deleteResponse.getResult() == DocWriteResponse.Result.NOT_FOUND) {
                listener.onFailure(new ResourceNotFoundException("Resource group " + resourceId + " not found."));
            } else {
                listener.onResponse(new Response("Resource group " + resourceId + " deleted successfully."));
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

    /**
     * Request object for DeleteSampleResourceGroup transport action
     */
    public static class Request extends ActionRequest implements DocRequest {

        private final String resourceId;

        public Request(String resourceId) {
            this.resourceId = resourceId;
        }

        public Request(StreamInput in) throws IOException {
            this.resourceId = in.readString();
        }

        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            out.writeString(this.resourceId);
        }

        @Override
        public ActionRequestValidationException validate() {
            return null;
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

    /**
     * Response to a DeleteSampleResourceGroupRequest
     */
    public static class Response extends ActionResponse implements ToXContentObject {
        private final String message;

        public Response(String message) {
            this.message = message;
        }

        public Response(final StreamInput in) throws IOException {
            message = in.readString();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeString(message);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            builder.field("message", message);
            builder.endObject();
            return builder;
        }
    }
}
