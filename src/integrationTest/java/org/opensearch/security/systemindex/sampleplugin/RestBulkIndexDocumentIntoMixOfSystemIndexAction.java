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

import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkRequestBuilder;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.PUT;
import static org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1.SYSTEM_INDEX_1;
import static org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin2.SYSTEM_INDEX_2;

public class RestBulkIndexDocumentIntoMixOfSystemIndexAction extends BaseRestHandler {

    private final Client client;
    private final PluginClient pluginClient;

    public RestBulkIndexDocumentIntoMixOfSystemIndexAction(Client client, PluginClient pluginClient) {
        this.client = client;
        this.pluginClient = pluginClient;
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(PUT, "/try-create-and-bulk-mixed-index"));
    }

    @Override
    public String getName() {
        return "test_bulk_index_document_into_mix_of_system_index_action";
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return new RestChannelConsumer() {

            @Override
            public void accept(RestChannel channel) throws Exception {
                BulkRequestBuilder builder = client.prepareBulk();
                builder.add(new IndexRequest(SYSTEM_INDEX_1).source("content", 1));
                builder.add(new IndexRequest(SYSTEM_INDEX_2).source("content", 1));
                builder.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                BulkRequest bulkRequest = builder.request();
                pluginClient.bulk(bulkRequest, ActionListener.wrap(r -> {
                    channel.sendResponse(new BytesRestResponse(RestStatus.OK, r.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS)));
                }, fr -> { channel.sendResponse(new BytesRestResponse(RestStatus.FORBIDDEN, String.valueOf(fr))); }));
            }
        };
    }
}
