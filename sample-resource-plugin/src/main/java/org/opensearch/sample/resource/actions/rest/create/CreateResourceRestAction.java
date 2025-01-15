/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.create;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.sample.SampleResource;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestRequest.Method.PUT;

public class CreateResourceRestAction extends BaseRestHandler {

    public CreateResourceRestAction() {}

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(PUT, "/_plugins/sample_resource_sharing/create"),
            new Route(POST, "/_plugins/sample_resource_sharing/update")
        );
    }

    @Override
    public String getName() {
        return "create_sample_resource";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        String name = (String) source.get("name");
        String description = source.containsKey("description") ? (String) source.get("description") : null;
        Map<String, String> attributes = source.containsKey("attributes") ? (Map<String, String>) source.get("attributes") : null;
        SampleResource resource = new SampleResource();
        resource.setName(name);
        resource.setDescription(description);
        resource.setAttributes(attributes);
        final CreateResourceRequest createSampleResourceRequest = new CreateResourceRequest(resource);
        return channel -> client.executeLocally(
            CreateResourceAction.INSTANCE,
            createSampleResourceRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
