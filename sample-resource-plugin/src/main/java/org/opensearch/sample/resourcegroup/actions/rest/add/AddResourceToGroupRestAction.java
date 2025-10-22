/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.add;

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
 * Rest Action to add a Sample Resource to a Group.
 */
public class AddResourceToGroupRestAction extends BaseRestHandler {

    public AddResourceToGroupRestAction() {}

    @Override
    public List<Route> routes() {
        return List.of(new Route(POST, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/group/add/{group_id}"));
    }

    @Override
    public String getName() {
        return "add_sample_resource_to_group";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        return switch (request.method()) {
            case POST -> addResourceToGroup(source, request.param("group_id"), client);
            default -> throw new IllegalArgumentException("Illegal method: " + request.method());
        };
    }

    private RestChannelConsumer addResourceToGroup(Map<String, Object> source, String groupId, NodeClient client) throws IOException {
        String resourceId = (String) source.get("resource_id");
        final AddResourceToGroupRequest addResourceToGroupRequest = new AddResourceToGroupRequest(groupId, resourceId);
        return channel -> client.executeLocally(
            AddResourceToGroupAction.INSTANCE,
            addResourceToGroupRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
