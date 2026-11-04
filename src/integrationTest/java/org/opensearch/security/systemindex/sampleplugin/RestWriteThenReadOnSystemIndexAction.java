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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;

import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * Indexes a document as the plugin subject without a refresh, then reads it back by id as the same subject.
 * Reports whether the read found the document, which it does only if the read is realtime. With {@code mget=true}
 * the read is a multi-get, which also asks for a missing document in {@code other_index}, if given.
 */
public class RestWriteThenReadOnSystemIndexAction extends BaseRestHandler {

    private final PluginClient pluginClient;

    /**
     * Creates the handler.
     * @param pluginClient client that runs each request as the plugin subject
     */
    public RestWriteThenReadOnSystemIndexAction(PluginClient pluginClient) {
        this.pluginClient = pluginClient;
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(PUT, "/write-then-read-on-system-index/{index}/{docId}"));
    }

    @Override
    public String getName() {
        return "test_write_then_read_on_system_index_action";
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        final String indexName = request.param("index");
        final String docId = request.param("docId");
        final boolean multiGet = request.paramAsBoolean("mget", false);
        final String otherIndex = request.param("other_index");
        return channel -> {
            IndexRequest indexRequest = new IndexRequest(indexName).id(docId).source("{\"content\":1}", XContentType.JSON);
            pluginClient.index(
                indexRequest,
                ActionListener.wrap(
                    indexResponse -> readBack(channel, indexName, docId, multiGet, otherIndex),
                    e -> sendFailure(channel, e)
                )
            );
        };
    }

    private void readBack(RestChannel channel, String indexName, String docId, boolean multiGet, String otherIndex) {
        if (!multiGet) {
            pluginClient.get(
                new GetRequest(indexName, docId),
                ActionListener.wrap(response -> sendFound(channel, response.isExists()), e -> sendFailure(channel, e))
            );
            return;
        }
        MultiGetRequest multiGetRequest = new MultiGetRequest().add(indexName, docId);
        if (otherIndex != null) {
            multiGetRequest.add(otherIndex, "missing");
        }
        pluginClient.multiGet(multiGetRequest, ActionListener.wrap(response -> {
            for (MultiGetItemResponse item : response.getResponses()) {
                if (item.isFailed()) {
                    sendFailure(channel, item.getFailure().getFailure());
                    return;
                }
            }
            sendFound(channel, response.getResponses()[0].getResponse().isExists());
        }, e -> sendFailure(channel, e)));
    }

    private static void sendFound(RestChannel channel, boolean found) throws Exception {
        channel.sendResponse(new BytesRestResponse(RestStatus.OK, channel.newBuilder().startObject().field("found", found).endObject()));
    }

    private static void sendFailure(RestChannel channel, Exception e) {
        try {
            channel.sendResponse(new BytesRestResponse(channel, e));
        } catch (IOException ioException) {
            ioException.addSuppressed(e);
            throw new UncheckedIOException(ioException);
        }
    }
}
