/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.secure.actions.rest.create;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_API_PREFIX;

/**
 * Rest action to trigger the sample plugin to run actions using its assigned PluginSubject
 *
 * Example payloads
 *
 * Cluster action:
 *
 * {
 *     "action": "cluster:monitor/health"
 * }
 *
 * Index action:
 *
 * {
 *     "action": "indices:admin/create",
 *     "indices": "test-index"
 * }
 */
public class SecurePluginRestAction extends BaseRestHandler {

    public SecurePluginRestAction() {}

    @Override
    public List<Route> routes() {
        return List.of(new Route(POST, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/run_action"));
    }

    @Override
    public String getName() {
        return "run_secure_plugin_test_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        switch (request.method()) {
            case POST:
                return runAction(source, client);
            default:
                throw new IllegalArgumentException("Illegal method: " + request.method());
        }
    }

    private RestChannelConsumer runAction(Map<String, Object> source, NodeClient client) {
        String action = (String) source.get("action");
        String index = source.containsKey("index") ? (String) source.get("index") : null;
        final SecurePluginRequest createSampleResourceRequest = new SecurePluginRequest(action, index);
        return channel -> client.executeLocally(
            SecurePluginAction.INSTANCE,
            createSampleResourceRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
