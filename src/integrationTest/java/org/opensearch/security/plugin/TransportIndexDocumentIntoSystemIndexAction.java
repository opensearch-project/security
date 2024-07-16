package org.opensearch.security.plugin;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.node.PluginAwareNodeClient;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportIndexDocumentIntoSystemIndexAction extends HandledTransportAction<
    IndexDocumentIntoSystemIndexRequest,
    IndexDocumentIntoSystemIndexResponse> {

    private final PluginAwareNodeClient pluginAwareClient;

    @Inject
    public TransportIndexDocumentIntoSystemIndexAction(
        final TransportService transportService,
        final ActionFilters actionFilters,
        final PluginAwareNodeClient pluginAwareClient
    ) {
        super(IndexDocumentIntoSystemIndexAction.NAME, transportService, actionFilters, IndexDocumentIntoSystemIndexRequest::new);
        this.pluginAwareClient = pluginAwareClient;
    }

    @Override
    protected void doExecute(
        Task task,
        IndexDocumentIntoSystemIndexRequest request,
        ActionListener<IndexDocumentIntoSystemIndexResponse> actionListener
    ) {
        String indexName = request.getIndexName();
        try (ThreadContext.StoredContext storedContext = pluginAwareClient.switchContext()) {
            pluginAwareClient.admin().indices().create(new CreateIndexRequest(indexName), ActionListener.wrap(r -> {
                pluginAwareClient.index(
                    new IndexRequest(indexName).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .source("{\"content\":1}", XContentType.JSON),
                    ActionListener.wrap(r2 -> {
                        String stashedContext = pluginAwareClient.threadPool()
                            .getThreadContext()
                            .getHeader(ThreadContext.PLUGIN_EXECUTION_CONTEXT);
                        actionListener.onResponse(new IndexDocumentIntoSystemIndexResponse(true, stashedContext));
                    }, e -> {
                        actionListener.onFailure(e);
                    })
                );
            }, e -> {
                actionListener.onFailure(e);
            }));
        }
    }
}
