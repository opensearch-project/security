/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.secure.actions.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.admin.cluster.health.ClusterHealthAction;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.indices.create.CreateIndexAction;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.sample.secure.actions.rest.create.SecurePluginAction;
import org.opensearch.sample.secure.actions.rest.create.SecurePluginRequest;
import org.opensearch.sample.secure.actions.rest.create.SecurePluginResponse;
import org.opensearch.sample.utils.RunAsSubjectClient;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

/**
 * Transport action for creating a new resource.
 */
public class SecurePluginTransportAction extends HandledTransportAction<SecurePluginRequest, SecurePluginResponse> {
    private static final Logger log = LogManager.getLogger(SecurePluginTransportAction.class);

    // TODO Get RunAsClient

    private final Client pluginClient;

    @Inject
    public SecurePluginTransportAction(TransportService transportService, ActionFilters actionFilters, RunAsSubjectClient pluginClient) {
        super(SecurePluginAction.NAME, transportService, actionFilters, SecurePluginRequest::new);
        this.pluginClient = pluginClient;
    }

    @Override
    protected void doExecute(Task task, SecurePluginRequest request, ActionListener<SecurePluginResponse> listener) {
        runAction(request, listener);
    }

    private void runAction(SecurePluginRequest request, ActionListener<SecurePluginResponse> listener) {
        String action = request.getAction();
        if (ClusterHealthAction.NAME.equals(action)) {
            pluginClient.execute(
                ClusterHealthAction.INSTANCE,
                new ClusterHealthRequest(),
                ActionListener.wrap(
                    clusterHealthResponse -> listener.onResponse(
                        new SecurePluginResponse(
                            String.valueOf(clusterHealthResponse.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                        )
                    ),
                    listener::onFailure
                )
            );
            return;
        } else if (CreateIndexAction.NAME.equals(action)) {
            String index = request.getIndex();
            pluginClient.execute(
                CreateIndexAction.INSTANCE,
                new CreateIndexRequest(index),
                ActionListener.wrap(
                    createIndexResponse -> listener.onResponse(
                        new SecurePluginResponse(
                            String.valueOf(createIndexResponse.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                        )
                    ),
                    listener::onFailure
                )
            );
            return;
        }

        listener.onResponse(new SecurePluginResponse("Unrecognized action: " + action));
    }
}
