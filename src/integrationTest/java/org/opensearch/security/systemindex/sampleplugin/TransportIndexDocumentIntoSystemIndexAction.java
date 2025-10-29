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

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

public class TransportIndexDocumentIntoSystemIndexAction extends HandledTransportAction<
    IndexDocumentIntoSystemIndexRequest,
    AcknowledgedResponse> {

    private final Client client;
    private final PluginClient pluginClient;

    @Inject
    public TransportIndexDocumentIntoSystemIndexAction(
        final TransportService transportService,
        final ActionFilters actionFilters,
        final Client client,
        final PluginClient pluginClient
    ) {
        super(IndexDocumentIntoSystemIndexAction.NAME, transportService, actionFilters, IndexDocumentIntoSystemIndexRequest::new);
        this.client = client;
        this.pluginClient = pluginClient;
    }

    @Override
    protected void doExecute(Task task, IndexDocumentIntoSystemIndexRequest request, ActionListener<AcknowledgedResponse> actionListener) {
        String indexName = request.getIndexName();
        String runAs = request.getRunAs();
        try {
            pluginClient.admin().indices().create(new CreateIndexRequest(indexName), ActionListener.wrap(r -> {
                if ("user".equalsIgnoreCase(runAs)) {
                    client.index(
                        new IndexRequest(indexName).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                            .source("{\"content\":1}", XContentType.JSON),
                        ActionListener.wrap(r2 -> {
                            actionListener.onResponse(new AcknowledgedResponse(true));
                        }, actionListener::onFailure)
                    );
                } else {
                    pluginClient.index(
                        new IndexRequest(indexName).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                            .source("{\"content\":1}", XContentType.JSON),
                        ActionListener.wrap(r2 -> {
                            actionListener.onResponse(new AcknowledgedResponse(true));
                        }, actionListener::onFailure)
                    );
                }
            }, actionListener::onFailure));
        } catch (Exception ex) {
            throw new RuntimeException("Unexpected error: " + ex.getMessage());
        }
    }
}
