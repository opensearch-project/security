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

import java.util.List;

import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.security.identity.PluginContextSwitcher;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.GET;

public class RestRunClusterHealthAction extends BaseRestHandler {

    private final Client client;
    private final PluginContextSwitcher contextSwitcher;

    public RestRunClusterHealthAction(Client client, PluginContextSwitcher contextSwitcher) {
        this.client = client;
        this.contextSwitcher = contextSwitcher;
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(GET, "/try-cluster-health/{runAs}"));
    }

    @Override
    public String getName() {
        return "test_run_cluster_health_action";
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String runAs = request.param("runAs");
        RunClusterHealthRequest runRequest = new RunClusterHealthRequest(runAs);
        return channel -> client.execute(RunClusterHealthAction.INSTANCE, runRequest, new RestToXContentListener<>(channel));
    }
}
