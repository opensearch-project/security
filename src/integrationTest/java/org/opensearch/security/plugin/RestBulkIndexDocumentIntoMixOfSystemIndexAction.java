/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.plugin;

import java.util.List;

import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkRequestBuilder;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.identity.PluginContextSwitcher;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.PUT;
import static org.opensearch.security.plugin.SystemIndexPlugin1.SYSTEM_INDEX_1;
import static org.opensearch.security.plugin.SystemIndexPlugin2.SYSTEM_INDEX_2;

public class RestBulkIndexDocumentIntoMixOfSystemIndexAction extends BaseRestHandler {

    private final Client client;
    private final PluginContextSwitcher contextSwitcher;

    public RestBulkIndexDocumentIntoMixOfSystemIndexAction(Client client, PluginContextSwitcher contextSwitcher) {
        this.client = client;
        this.contextSwitcher = contextSwitcher;
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
                contextSwitcher.runAs(() -> {
                    BulkRequestBuilder builder = client.prepareBulk();
                    builder.add(new IndexRequest(SYSTEM_INDEX_1).source("{\"content\":1}", XContentType.JSON));
                    builder.add(new IndexRequest(SYSTEM_INDEX_2).source("{\"content\":1}", XContentType.JSON));
                    builder.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                    BulkRequest bulkRequest = builder.request();
                    client.bulk(bulkRequest, ActionListener.wrap(r -> {
                        channel.sendResponse(
                            new BytesRestResponse(RestStatus.OK, r.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS))
                        );
                    }, fr -> { channel.sendResponse(new BytesRestResponse(RestStatus.FORBIDDEN, String.valueOf(fr))); }));
                    return null;
                });
            }
        };
    }
}
