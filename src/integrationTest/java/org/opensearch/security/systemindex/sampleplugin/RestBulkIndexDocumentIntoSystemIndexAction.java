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

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkRequestBuilder;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.xcontent.XContentType;
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

public class RestBulkIndexDocumentIntoSystemIndexAction extends BaseRestHandler {

    private final Client client;
    private final PluginClient pluginClient;

    public RestBulkIndexDocumentIntoSystemIndexAction(Client client, PluginClient pluginClient) {
        this.client = client;
        this.pluginClient = pluginClient;
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(PUT, "/try-create-and-bulk-index/{index}"));
    }

    @Override
    public String getName() {
        return "test_bulk_index_document_into_system_index_action";
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String indexName = request.param("index");
        return new RestChannelConsumer() {

            @Override
            public void accept(RestChannel channel) throws Exception {
                pluginClient.admin().indices().create(new CreateIndexRequest(indexName), ActionListener.wrap(r -> {
                    BulkRequestBuilder builder = client.prepareBulk();
                    builder.add(new IndexRequest(indexName).source("{\"content\":1}", XContentType.JSON));
                    builder.add(new IndexRequest(indexName).source("{\"content\":2}", XContentType.JSON));
                    builder.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                    BulkRequest bulkRequest = builder.request();
                    pluginClient.bulk(bulkRequest, ActionListener.wrap(r2 -> {
                        channel.sendResponse(
                            new BytesRestResponse(RestStatus.OK, r.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS))
                        );
                    }, fr -> { channel.sendResponse(new BytesRestResponse(RestStatus.FORBIDDEN, String.valueOf(fr))); }));
                }, fr -> { channel.sendResponse(new BytesRestResponse(RestStatus.FORBIDDEN, String.valueOf(fr))); }));
            }
        };
    }
}
