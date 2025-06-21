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

import org.opensearch.action.update.UpdateRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.PUT;

public class RestUpdateOnSystemIndexAction extends BaseRestHandler {

    private final PluginClient pluginClient;

    public RestUpdateOnSystemIndexAction(PluginClient pluginClient) {
        this.pluginClient = pluginClient;
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(PUT, "/update-on-system-index/{index}/{docId}"));
    }

    @Override
    public String getName() {
        return "test_update_on_system_index_action";
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String indexName = request.param("index");
        String docId = request.param("docId");
        return new RestChannelConsumer() {

            @Override
            public void accept(RestChannel channel) throws Exception {
                UpdateRequest updateRequest = new UpdateRequest();
                updateRequest.index(indexName);
                updateRequest.id(docId);
                updateRequest.doc("content", 3);
                pluginClient.update(updateRequest, ActionListener.wrap(r -> {
                    channel.sendResponse(new BytesRestResponse(RestStatus.OK, r.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS)));
                }, fr -> { channel.sendResponse(new BytesRestResponse(RestStatus.FORBIDDEN, String.valueOf(fr))); }));
            }
        };
    }
}
