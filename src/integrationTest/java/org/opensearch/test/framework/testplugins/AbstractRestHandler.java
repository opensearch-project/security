package org.opensearch.test.framework.testplugins;

import org.opensearch.ExceptionsHelper;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestStatusToXContentListener;
import org.opensearch.test.framework.testplugins.dummyprotected.dummyaction.DummyAction;
import org.opensearch.test.framework.testplugins.dummyprotected.dummyaction.DummyRequest;

import java.io.IOException;

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

    private void handlePost(RestChannel channel, RestRequest request, NodeClient client) {
        notImplemented(channel, request.method());
    }

    private void handleGet(RestChannel channel, RestRequest request, NodeClient client) {
        String message = request.param("message");
        DummyRequest dummyRequest = new DummyRequest(message);
        client.execute(DummyAction.INSTANCE, dummyRequest, new RestStatusToXContentListener<>(channel));
    }
}
