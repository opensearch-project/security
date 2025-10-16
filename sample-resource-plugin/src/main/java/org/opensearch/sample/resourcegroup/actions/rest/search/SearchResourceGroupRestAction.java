/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.search;

import java.io.IOException;
import java.util.List;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_API_PREFIX;

/**
 * Rest action to search sample resource(s)
 */
public class SearchResourceGroupRestAction extends BaseRestHandler {

    public SearchResourceGroupRestAction() {}

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(GET, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/group/search"),
            new Route(POST, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/group/search")
        );
    }

    @Override
    public String getName() {
        return "search_sample_resource_group";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        final SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();

        if (request.hasContentOrSourceParam()) {
            try (XContentParser parser = request.contentOrSourceParamParser()) {
                searchSourceBuilder.parseXContent(parser);
            }
        } else {
            // Optional: default query if no body is provided
            searchSourceBuilder.query(QueryBuilders.matchAllQuery());
        }

        SearchRequest searchRequest = new SearchRequest().indices(RESOURCE_INDEX_NAME).source(searchSourceBuilder);

        return channel -> client.executeLocally(SearchResourceGroupAction.INSTANCE, searchRequest, new RestToXContentListener<>(channel));
    }
}
