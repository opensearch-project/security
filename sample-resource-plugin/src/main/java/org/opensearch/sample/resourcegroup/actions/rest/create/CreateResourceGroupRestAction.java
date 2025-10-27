/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.create;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.sample.SampleResourceGroup;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestRequest.Method.PUT;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_API_PREFIX;

/**
 * Rest Action to create a Sample Resource Group. Registers Create and Update REST APIs.
 */
public class CreateResourceGroupRestAction extends BaseRestHandler {

    public CreateResourceGroupRestAction() {}

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(PUT, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/group/create"),
            new Route(POST, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/group/update/{resource_id}")
        );
    }

    @Override
    public String getName() {
        return "create_update_sample_resource_group";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        return switch (request.method()) {
            case PUT -> createResource(source, client);
            case POST -> updateResource(source, request.param("resource_id"), client);
            default -> throw new IllegalArgumentException("Illegal method: " + request.method());
        };
    }

    private RestChannelConsumer updateResource(Map<String, Object> source, String resourceId, NodeClient client) throws IOException {
        String name = (String) source.get("name");
        String description = source.containsKey("description") ? (String) source.get("description") : null;
        SampleResourceGroup resourceGroup = new SampleResourceGroup();
        resourceGroup.setName(name);
        resourceGroup.setDescription(description);
        final UpdateResourceGroupRequest updateResourceRequest = new UpdateResourceGroupRequest(resourceId, resourceGroup);
        return channel -> client.executeLocally(
            UpdateResourceGroupAction.INSTANCE,
            updateResourceRequest,
            new RestToXContentListener<>(channel)
        );
    }

    private RestChannelConsumer createResource(Map<String, Object> source, NodeClient client) throws IOException {
        String name = (String) source.get("name");
        String description = source.containsKey("description") ? (String) source.get("description") : null;
        SampleResourceGroup resourceGroup = new SampleResourceGroup();
        resourceGroup.setName(name);
        resourceGroup.setDescription(description);
        final CreateResourceGroupRequest createSampleResourceRequest = new CreateResourceGroupRequest(resourceGroup);
        return channel -> client.executeLocally(
            CreateResourceGroupAction.INSTANCE,
            createSampleResourceRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
