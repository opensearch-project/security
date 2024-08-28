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

import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.identity.IdentityService;
import org.opensearch.identity.Subject;
import org.opensearch.security.identity.PluginContextSwitcher;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportRunClusterHealthAction extends HandledTransportAction<RunClusterHealthRequest, RunClusterHealthResponse> {

    private final Client client;
    private final ThreadPool threadPool;
    private final PluginContextSwitcher contextSwitcher;
    private final IdentityService identityService;

    @Inject
    public TransportRunClusterHealthAction(
        final TransportService transportService,
        final ActionFilters actionFilters,
        final Client client,
        final ThreadPool threadPool,
        final PluginContextSwitcher contextSwitcher,
        final IdentityService identityService
    ) {
        super(RunClusterHealthAction.NAME, transportService, actionFilters, RunClusterHealthRequest::new);
        this.client = client;
        this.threadPool = threadPool;
        this.contextSwitcher = contextSwitcher;
        this.identityService = identityService;
    }

    @Override
    protected void doExecute(Task task, RunClusterHealthRequest request, ActionListener<RunClusterHealthResponse> actionListener) {
        String runAs = request.getRunAs();
        if ("user".equalsIgnoreCase(runAs)) {
            Subject user = identityService.getCurrentSubject();
            try {
                user.runAs(() -> {
                    ActionListener<ClusterHealthResponse> chr = ActionListener.wrap(
                        r -> { actionListener.onResponse(new RunClusterHealthResponse(true)); },
                        actionListener::onFailure
                    );
                    client.admin().cluster().health(new ClusterHealthRequest(), chr);
                    return null;
                });
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else if ("plugin".equalsIgnoreCase(runAs)) {
            contextSwitcher.runAs(() -> {
                ActionListener<ClusterHealthResponse> chr = ActionListener.wrap(
                    r -> { actionListener.onResponse(new RunClusterHealthResponse(true)); },
                    actionListener::onFailure
                );
                client.admin().cluster().health(new ClusterHealthRequest(), chr);
                return null;
            });
        } else {
            ActionListener<ClusterHealthResponse> chr = ActionListener.wrap(
                r -> { actionListener.onResponse(new RunClusterHealthResponse(true)); },
                actionListener::onFailure
            );
            client.admin().cluster().health(new ClusterHealthRequest(), chr);
        }
    }
}
