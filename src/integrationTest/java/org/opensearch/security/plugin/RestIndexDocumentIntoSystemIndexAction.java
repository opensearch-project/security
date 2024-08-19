package org.opensearch.security.plugin;

import java.util.List;

import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.PUT;

public class RestIndexDocumentIntoSystemIndexAction extends BaseRestHandler {

    private final Client client;

    public RestIndexDocumentIntoSystemIndexAction(Client client) {
        this.client = client;
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(PUT, "/_plugins/system-index/{index}"));
    }

    @Override
    public String getName() {
        return "test_index_document_into_system_index_action";
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String indexName = request.param("index");
        IndexDocumentIntoSystemIndexRequest indexRequest = new IndexDocumentIntoSystemIndexRequest(indexName);
        return channel -> client.execute(IndexDocumentIntoSystemIndexAction.INSTANCE, indexRequest, new RestToXContentListener<>(channel));
    }
}
