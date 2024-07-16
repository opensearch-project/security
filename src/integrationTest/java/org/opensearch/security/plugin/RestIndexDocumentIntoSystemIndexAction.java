package org.opensearch.security.plugin;

import java.util.List;

import org.opensearch.client.node.NodeClient;
import org.opensearch.client.node.PluginAwareNodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.PUT;

public class RestIndexDocumentIntoSystemIndexAction extends BaseRestHandler {

    private final PluginAwareNodeClient pluginAwareClient;

    public RestIndexDocumentIntoSystemIndexAction(PluginAwareNodeClient pluginAwareClient) {
        this.pluginAwareClient = pluginAwareClient;
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
        // String stashedContext;
        String indexName = request.param("index");
        // System.out.println("Received request for index: " + indexName);
        // try (ThreadContext.StoredContext storedContext = pluginAwareClient.switchContext()) {
        // CreateIndexResponse cir = client.admin().indices().create(new CreateIndexRequest(indexName)).actionGet();
        // client.index(
        // new IndexRequest(indexName).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
        // .source("{\"content\":1}", XContentType.JSON)
        // );
        // stashedContext = pluginAwareClient.threadPool().getThreadContext().getHeader(ThreadContext.PLUGIN_EXECUTION_CONTEXT);
        // } catch (Exception e) {
        // RestResponse failureResponse = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        // return channel -> channel.sendResponse(failureResponse);
        // }
        // RestResponse response = new BytesRestResponse(RestStatus.OK, stashedContext);
        // return channel -> channel.sendResponse(response);
        IndexDocumentIntoSystemIndexRequest indexRequest = new IndexDocumentIntoSystemIndexRequest(indexName);
        return channel -> client.execute(IndexDocumentIntoSystemIndexAction.INSTANCE, indexRequest, new RestToXContentListener<>(channel));
    }
}
