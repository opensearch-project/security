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
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.sample.SampleResource;
import org.opensearch.sample.SampleResourceScope;
import org.opensearch.sample.resource.actions.rest.get.GetResourceAction;
import org.opensearch.sample.resource.actions.rest.get.GetResourceRequest;
import org.opensearch.sample.resource.actions.rest.get.GetResourceResponse;
import org.opensearch.sample.resource.client.ResourceSharingClientAccessor;
import org.opensearch.security.client.resources.ResourceSharingClient;
import org.opensearch.security.spi.resources.exceptions.ResourceSharingException;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for getting a resource
 */
public class GetResourceTransportAction extends HandledTransportAction<GetResourceRequest, GetResourceResponse> {
    private static final Logger log = LogManager.getLogger(GetResourceTransportAction.class);

    private final TransportService transportService;
    private final NodeClient nodeClient;
    private final Settings settings;

    @Inject
    public GetResourceTransportAction(
        Settings settings,
        TransportService transportService,
        ActionFilters actionFilters,
        NodeClient nodeClient
    ) {
        super(GetResourceAction.NAME, transportService, actionFilters, GetResourceRequest::new);
        this.transportService = transportService;
        this.nodeClient = nodeClient;
        this.settings = settings;
    }

    @Override
    protected void doExecute(Task task, GetResourceRequest request, ActionListener<GetResourceResponse> listener) {
        if (request.getResourceId() == null || request.getResourceId().isEmpty()) {
            listener.onFailure(new IllegalArgumentException("Resource ID cannot be null or empty"));
            return;
        }

        // Check permission to resource
        ResourceSharingClient resourceSharingClient = ResourceSharingClientAccessor.getResourceSharingClient(nodeClient, settings);
        resourceSharingClient.verifyResourceAccess(
            request.getResourceId(),
            RESOURCE_INDEX_NAME,
            SampleResourceScope.PUBLIC.value(),
            ActionListener.wrap(isAuthorized -> {
                if (!isAuthorized) {
                    listener.onFailure(
                        new ResourceSharingException("Current user is not authorized to access resource: " + request.getResourceId())
                    );
                    return;
                }

                getResourceAction(request, listener);
            }, listener::onFailure)
        );
    }

    private void getResourceAction(GetResourceRequest request, ActionListener<GetResourceResponse> listener) {
        ThreadContext threadContext = transportService.getThreadPool().getThreadContext();
        try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
            getResource(request, ActionListener.wrap(getResponse -> {
                if (getResponse.isSourceEmpty()) {
                    listener.onFailure(new ResourceNotFoundException("Resource " + request.getResourceId() + " not found."));
                } else {
                    try (
                        XContentParser parser = XContentType.JSON.xContent()
                            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, getResponse.getSourceAsString())
                    ) {
                        listener.onResponse(new GetResourceResponse(SampleResource.fromXContent(parser)));
                    }
                }
            }, listener::onFailure));
        }
    }

    private void getResource(GetResourceRequest request, ActionListener<GetResponse> listener) {
        GetRequest getRequest = new GetRequest(RESOURCE_INDEX_NAME, request.getResourceId());

        nodeClient.get(getRequest, listener);
    }

}
