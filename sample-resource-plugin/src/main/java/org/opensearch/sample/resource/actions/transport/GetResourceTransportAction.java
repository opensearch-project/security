/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.transport;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.sample.SampleResource;
import org.opensearch.sample.resource.actions.rest.get.GetResourceAction;
import org.opensearch.sample.resource.actions.rest.get.GetResourceRequest;
import org.opensearch.sample.resource.actions.rest.get.GetResourceResponse;
import org.opensearch.sample.utils.PluginClient;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for getting a resource
 */
public class GetResourceTransportAction extends HandledTransportAction<GetResourceRequest, GetResourceResponse> {

    private final PluginClient pluginClient;

    @Inject
    public GetResourceTransportAction(TransportService transportService, ActionFilters actionFilters, PluginClient pluginClient) {
        super(GetResourceAction.NAME, transportService, actionFilters, GetResourceRequest::new);
        this.pluginClient = pluginClient;
    }

    @Override
    protected void doExecute(Task task, GetResourceRequest request, ActionListener<GetResourceResponse> listener) {
        String resourceId = request.getResourceId();

        if (Strings.isNullOrEmpty(resourceId)) {
            fetchAllResources(listener);
        } else {
            fetchResourceById(resourceId, listener);
        }
    }

    private void fetchAllResources(ActionListener<GetResourceResponse> listener) {
        SearchSourceBuilder ssb = new SearchSourceBuilder().size(1000).query(QueryBuilders.matchAllQuery());

        SearchRequest req = new SearchRequest(RESOURCE_INDEX_NAME).source(ssb);
        pluginClient.search(req, ActionListener.wrap(searchResponse -> {
            SearchHit[] hits = searchResponse.getHits().getHits();

            Set<SampleResource> resources = Arrays.stream(hits).map(hit -> {
                try {
                    return parseResource(hit.getSourceAsString());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }).collect(Collectors.toSet());
            listener.onResponse(new GetResourceResponse(resources));

        }, listener::onFailure));
    }

    private void fetchResourceById(String resourceId, ActionListener<GetResourceResponse> listener) {
        GetRequest req = new GetRequest(RESOURCE_INDEX_NAME, resourceId);
        pluginClient.get(req, ActionListener.wrap(resp -> {
            if (resp.isSourceEmpty()) {
                listener.onFailure(new ResourceNotFoundException("Resource " + resourceId + " not found."));
            } else {
                System.out.println("Get Resource Response: " + resp.getSourceAsString());
                SampleResource resource = parseResource(resp.getSourceAsString());
                listener.onResponse(new GetResourceResponse(Set.of(resource)));
            }
        }, listener::onFailure));
    }

    private SampleResource parseResource(String json) throws IOException {
        try (
            XContentParser parser = XContentType.JSON.xContent()
                .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, json)
        ) {
            return SampleResource.fromXContent(parser);
        }
    }

}
