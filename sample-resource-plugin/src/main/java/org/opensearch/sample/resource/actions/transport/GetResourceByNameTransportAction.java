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

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.sample.SampleResource;
import org.opensearch.sample.resource.actions.rest.get.GetResourceByNameAction;
import org.opensearch.sample.resource.actions.rest.get.GetResourceByNameRequest;
import org.opensearch.sample.resource.actions.rest.get.GetResourceResponse;
import org.opensearch.sample.utils.PluginClient;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for getting a resource by its name. It performs no access check of its own: the plugin's gating
 * resource resolver names the resource that governs the request, and the security plugin authorizes it before this action
 * runs.
 */
public class GetResourceByNameTransportAction extends HandledTransportAction<GetResourceByNameRequest, GetResourceResponse> {

    private final PluginClient pluginClient;

    @Inject
    public GetResourceByNameTransportAction(TransportService transportService, ActionFilters actionFilters, PluginClient pluginClient) {
        super(GetResourceByNameAction.NAME, transportService, actionFilters, GetResourceByNameRequest::new);
        this.pluginClient = pluginClient;
    }

    @Override
    protected void doExecute(Task task, GetResourceByNameRequest request, ActionListener<GetResourceResponse> listener) {
        SearchSourceBuilder source = new SearchSourceBuilder().size(1)
            .query(QueryBuilders.termQuery("name.keyword", request.getResourceName()));

        pluginClient.search(new SearchRequest(RESOURCE_INDEX_NAME).source(source), ActionListener.wrap(searchResponse -> {
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

    private SampleResource parseResource(String json) throws IOException {
        try (
            XContentParser parser = XContentType.JSON.xContent()
                .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, json)
        ) {
            return SampleResource.fromXContent(parser);
        }
    }

}
