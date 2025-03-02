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

import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.sample.SampleResource;
import org.opensearch.sample.resource.actions.rest.get.GetResourceAction;
import org.opensearch.sample.resource.actions.rest.get.GetResourceRequest;
import org.opensearch.sample.resource.actions.rest.get.GetResourceResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

public class GetResourceTransportAction extends HandledTransportAction<GetResourceRequest, GetResourceResponse> {
    private static final Logger log = LogManager.getLogger(GetResourceTransportAction.class);

    private final TransportService transportService;
    private final Client nodeClient;

    @Inject
    public GetResourceTransportAction(TransportService transportService, ActionFilters actionFilters, Client nodeClient) {
        super(GetResourceAction.NAME, transportService, actionFilters, GetResourceRequest::new);
        this.transportService = transportService;
        this.nodeClient = nodeClient;
    }

    @Override
    protected void doExecute(Task task, GetResourceRequest request, ActionListener<GetResourceResponse> listener) {
        if (request.getResourceId() == null || request.getResourceId().isEmpty()) {
            listener.onFailure(new IllegalArgumentException("Resource ID cannot be null or empty"));
            return;
        }

        ThreadContext threadContext = transportService.getThreadPool().getThreadContext();
        try (ThreadContext.StoredContext ignore = threadContext.stashContext()) {
            getResource(request, ActionListener.wrap(getResponse -> {
                if (getResponse.isSourceEmpty()) {
                    listener.onFailure(new ResourceNotFoundException("Resource " + request.getResourceId() + " not found."));
                } else {
                    // String jsonString = XContentFactory.jsonBuilder().map(getResponse.getSourceAsMap()).toString();
                    try (
                        XContentParser parser = XContentType.JSON.xContent()
                            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, getResponse.getSourceAsString())
                    ) {
                        listener.onResponse(new GetResourceResponse(SampleResource.fromXContent(parser)));
                    } catch (IllegalArgumentException e) {
                        throw new IllegalArgumentException("Invalid share_with structure: " + e.getMessage(), e);
                    }
                }
            }, exception -> {
                log.error("Failed to fetch resource: " + request.getResourceId(), exception);
                listener.onFailure(exception);
            }));
        }
    }

    private void getResource(GetResourceRequest request, ActionListener<GetResponse> listener) {
        XContentBuilder builder;
        try {
            builder = JsonXContent.contentBuilder()
                .startObject()
                .field("resource_id", request.getResourceId())
                .field("resource_index", RESOURCE_INDEX_NAME)
                .field("scope", "string_value") // Modify as needed
                .endObject();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        GetRequest getRequest = new GetRequest(RESOURCE_INDEX_NAME, request.getResourceId());

        nodeClient.get(getRequest, listener);
    }

}
