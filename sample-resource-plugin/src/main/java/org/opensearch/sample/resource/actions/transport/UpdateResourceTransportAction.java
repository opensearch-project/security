/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.transport;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.sample.resource.actions.rest.create.*;
import org.opensearch.security.spi.resources.Resource;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

public class UpdateResourceTransportAction extends HandledTransportAction<UpdateResourceRequest, CreateResourceResponse> {
    private static final Logger log = LogManager.getLogger(UpdateResourceTransportAction.class);

    private final TransportService transportService;
    private final Client nodeClient;

    @Inject
    public UpdateResourceTransportAction(TransportService transportService, ActionFilters actionFilters, Client nodeClient) {
        super(UpdateResourceAction.NAME, transportService, actionFilters, UpdateResourceRequest::new);
        this.transportService = transportService;
        this.nodeClient = nodeClient;
    }

    @Override
    protected void doExecute(Task task, UpdateResourceRequest request, ActionListener<CreateResourceResponse> listener) {
        ThreadContext threadContext = transportService.getThreadPool().getThreadContext();
        try (ThreadContext.StoredContext ignore = threadContext.stashContext()) {
            updateResource(request, listener);
            listener.onResponse(
                new CreateResourceResponse("Resource " + request.getResource().getResourceName() + " updated successfully.")
            );
        } catch (Exception e) {
            log.info("Failed to update resource: {}", request.getResourceId(), e);
            listener.onFailure(e);
        }
    }

    private void updateResource(UpdateResourceRequest request, ActionListener<CreateResourceResponse> listener) {
        String resourceId = request.getResourceId();
        Resource sample = request.getResource();
        try (XContentBuilder builder = jsonBuilder()) {
            UpdateRequest ur = new UpdateRequest(RESOURCE_INDEX_NAME, resourceId).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .doc(sample.toXContent(builder, ToXContent.EMPTY_PARAMS));

            log.info("Update Request: {}", ur.toString());

            nodeClient.update(
                ur,
                ActionListener.wrap(updateResponse -> { log.info("Updated resource: {}", updateResponse.toString()); }, listener::onFailure)
            );
        } catch (IOException e) {
            listener.onFailure(new RuntimeException(e));
        }

    }
}
