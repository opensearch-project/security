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

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.identity.IdentityService;
import org.opensearch.identity.Subject;
import org.opensearch.security.identity.PluginContextSwitcher;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportIndexDocumentIntoSystemIndexAction extends HandledTransportAction<
    IndexDocumentIntoSystemIndexRequest,
    IndexDocumentIntoSystemIndexResponse> {

    private final Client client;
    private final ThreadPool threadPool;
    private final PluginContextSwitcher contextSwitcher;
    private final IdentityService identityService;

    @Inject
    public TransportIndexDocumentIntoSystemIndexAction(
        final TransportService transportService,
        final ActionFilters actionFilters,
        final Client client,
        final ThreadPool threadPool,
        final PluginContextSwitcher contextSwitcher,
        final IdentityService identityService
    ) {
        super(IndexDocumentIntoSystemIndexAction.NAME, transportService, actionFilters, IndexDocumentIntoSystemIndexRequest::new);
        this.client = client;
        this.threadPool = threadPool;
        this.contextSwitcher = contextSwitcher;
        this.identityService = identityService;
    }

    @Override
    protected void doExecute(
        Task task,
        IndexDocumentIntoSystemIndexRequest request,
        ActionListener<IndexDocumentIntoSystemIndexResponse> actionListener
    ) {
        String indexName = request.getIndexName();
        String runAs = request.getRunAs();
        Subject userSubject = identityService.getCurrentSubject();
        try {
            contextSwitcher.runAs(() -> {
                client.admin().indices().create(new CreateIndexRequest(indexName), ActionListener.wrap(r -> {
                    if ("user".equalsIgnoreCase(runAs)) {
                        userSubject.runAs(() -> {
                            client.index(
                                new IndexRequest(indexName).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                                    .source("{\"content\":1}", XContentType.JSON),
                                ActionListener.wrap(r2 -> {
                                    User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                                    actionListener.onResponse(new IndexDocumentIntoSystemIndexResponse(true, user.getName()));
                                }, actionListener::onFailure)
                            );
                            return null;
                        });
                    } else {
                        client.index(
                            new IndexRequest(indexName).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                                .source("{\"content\":1}", XContentType.JSON),
                            ActionListener.wrap(r2 -> {
                                User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                                actionListener.onResponse(new IndexDocumentIntoSystemIndexResponse(true, user.getName()));
                            }, actionListener::onFailure)
                        );
                    }
                }, actionListener::onFailure));
                return null;
            });
        } catch (Exception ex) {
            throw new RuntimeException("Unexpected error: " + ex.getMessage());
        }
    }
}
