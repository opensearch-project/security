/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.testplugins;

import java.io.IOException;

import org.opensearch.ExceptionsHelper;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;

public class AbstractRestHandler extends BaseRestHandler {

    @Override
    public String getName() {
        return getClass().getSimpleName();
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        switch (request.method()) {
            case GET:
                return channel -> handleGet(channel, request, client);
            case POST:
                return channel -> handlePost(channel, request, client);
            default:
                throw new IllegalArgumentException(request.method() + " not supported");
        }
    }

    private void notImplemented(RestChannel channel, RestRequest.Method method) {
        try {
            final XContentBuilder builder = channel.newBuilder();
            builder.startObject();
            builder.field("status", RestStatus.NOT_IMPLEMENTED.name());
            builder.field("message", "Method " + method + " not implemented.");
            builder.endObject();
            channel.sendResponse(new BytesRestResponse(RestStatus.NOT_IMPLEMENTED, builder));
        } catch (IOException e) {
            throw ExceptionsHelper.convertToOpenSearchException(e);
        }
    }

    public void handlePost(RestChannel channel, RestRequest request, NodeClient client) {
        notImplemented(channel, request.method());
    }

    public void handleGet(RestChannel channel, RestRequest request, NodeClient client) {
        notImplemented(channel, request.method());
    }
}
