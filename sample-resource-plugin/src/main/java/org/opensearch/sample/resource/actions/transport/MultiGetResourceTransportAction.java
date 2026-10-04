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
import java.util.List;
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
import org.opensearch.sample.resource.actions.rest.get.GetResourceResponse;
import org.opensearch.sample.resource.actions.rest.get.MultiGetResourceAction;
import org.opensearch.sample.resource.actions.rest.get.MultiGetResourceRequest;
import org.opensearch.sample.utils.PluginClient;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Transport action for getting several resources in one request. It performs no access check of its own: the request
 * names its ids, so the security plugin authorizes all of them before this action runs.
 */
public class MultiGetResourceTransportAction extends HandledTransportAction<MultiGetResourceRequest, GetResourceResponse> {

    private final PluginClient pluginClient;

    @Inject
    public MultiGetResourceTransportAction(TransportService transportService, ActionFilters actionFilters, PluginClient pluginClient) {
        super(MultiGetResourceAction.NAME, transportService, actionFilters, MultiGetResourceRequest::new);
        this.pluginClient = pluginClient;
    }

    @Override
    protected void doExecute(Task task, MultiGetResourceRequest request, ActionListener<GetResourceResponse> listener) {
        List<String> resourceIds = request.ids();

        SearchSourceBuilder ssb = new SearchSourceBuilder().size(resourceIds.size())
            .query(QueryBuilders.idsQuery().addIds(resourceIds.toArray(new String[0])));

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

    private SampleResource parseResource(String json) throws IOException {
        try (
            XContentParser parser = XContentType.JSON.xContent()
                .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, json)
        ) {
            return SampleResource.fromXContent(parser);
        }
    }

}
