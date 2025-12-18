/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.systemindex.sampleplugin;

import java.util.List;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.node.NodeClient;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1.SYSTEM_INDEX_1;
import static org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin2.SYSTEM_INDEX_2;

public class RestSearchOnMixOfSystemIndexAction extends BaseRestHandler {

    private final PluginClient pluginClient;

    public RestSearchOnMixOfSystemIndexAction(PluginClient pluginClient) {
        this.pluginClient = pluginClient;
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(GET, "/search-on-mixed-system-index"));
    }

    @Override
    public String getName() {
        return "test_search_on_mix_of_system_index_action";
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return new RestChannelConsumer() {

            @Override
            public void accept(RestChannel channel) throws Exception {
                SearchRequest searchRequest = new SearchRequest(SYSTEM_INDEX_1, SYSTEM_INDEX_2);
                SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
                sourceBuilder.query(QueryBuilders.matchAllQuery());
                searchRequest.source(sourceBuilder);
                pluginClient.search(searchRequest, ActionListener.wrap(r -> {
                    channel.sendResponse(new BytesRestResponse(RestStatus.OK, r.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS)));
                }, fr -> { channel.sendResponse(new BytesRestResponse(RestStatus.FORBIDDEN, String.valueOf(fr))); }));
            }
        };
    }
}
