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

// CS-SUPPRESS-SINGLE: RegexpSingleline It is not possible to use phrase "cluster manager" instead of master here
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
// CS-ENFORCE-SINGLE

public class TransportRunClusterHealthAction extends HandledTransportAction<RunClusterHealthRequest, AcknowledgedResponse> {

    private final Client client;
    private final RunAsSubjectClient pluginClient;

    @Inject
    public TransportRunClusterHealthAction(
        final TransportService transportService,
        final ActionFilters actionFilters,
        final Client client,
        final RunAsSubjectClient pluginClient
    ) {
        super(RunClusterHealthAction.NAME, transportService, actionFilters, RunClusterHealthRequest::new);
        this.client = client;
        this.pluginClient = pluginClient;
    }

    @Override
    protected void doExecute(Task task, RunClusterHealthRequest request, ActionListener<AcknowledgedResponse> actionListener) {
        String runAs = request.getRunAs();
        if ("plugin".equalsIgnoreCase(runAs)) {
            ActionListener<ClusterHealthResponse> chr = ActionListener.wrap(
                r -> { actionListener.onResponse(new AcknowledgedResponse(true)); },
                actionListener::onFailure
            );
            pluginClient.admin().cluster().health(new ClusterHealthRequest(), chr);
        } else {
            // run in the authenticated user context
            ActionListener<ClusterHealthResponse> chr = ActionListener.wrap(
                r -> { actionListener.onResponse(new AcknowledgedResponse(true)); },
                actionListener::onFailure
            );
            client.admin().cluster().health(new ClusterHealthRequest(), chr);
        }
    }
}
