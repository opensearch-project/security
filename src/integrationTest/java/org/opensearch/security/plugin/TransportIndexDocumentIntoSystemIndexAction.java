package org.opensearch.security.plugin;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.identity.PluginSubject;
import org.opensearch.security.identity.ContextProvidingPluginSubject;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportIndexDocumentIntoSystemIndexAction extends HandledTransportAction<
    IndexDocumentIntoSystemIndexRequest,
    IndexDocumentIntoSystemIndexResponse> {

    private final Client client;
    private final PluginSubject pluginSystemSubject;

    @Inject
    public TransportIndexDocumentIntoSystemIndexAction(
        final TransportService transportService,
        final ActionFilters actionFilters,
        final Client client,
        final TransportActionDependencies deps
    ) {
        super(IndexDocumentIntoSystemIndexAction.NAME, transportService, actionFilters, IndexDocumentIntoSystemIndexRequest::new);
        this.client = client;
        this.pluginSystemSubject = deps.getPluginSystemSubject();
    }

    @Override
    protected void doExecute(
        Task task,
        IndexDocumentIntoSystemIndexRequest request,
        ActionListener<IndexDocumentIntoSystemIndexResponse> actionListener
    ) {
        String indexName = request.getIndexName();
        try {
            pluginSystemSubject.runAs(() -> {
                client.admin().indices().create(new CreateIndexRequest(indexName), ActionListener.wrap(r -> {
                    client.index(
                        new IndexRequest(indexName).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                            .source("{\"content\":1}", XContentType.JSON),
                        ActionListener.wrap(r2 -> {
                            String subjectHeader = client.threadPool()
                                .getThreadContext()
                                .getHeader(ContextProvidingPluginSubject.SUBJECT_HEADER);
                            actionListener.onResponse(new IndexDocumentIntoSystemIndexResponse(true, subjectHeader));
                        }, actionListener::onFailure)
                    );
                }, actionListener::onFailure));
                return null;
            });
        } catch (Exception ex) {
            throw new RuntimeException("Unexpected error: " + ex.getMessage());
        }
    }
}
