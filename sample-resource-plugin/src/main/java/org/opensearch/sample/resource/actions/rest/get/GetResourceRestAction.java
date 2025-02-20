/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.get;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.sample.SampleResource;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.*;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_API_PREFIX;

public class GetResourceRestAction extends BaseRestHandler {

    public GetResourceRestAction() {}

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(GET, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/get/{resourceId}"),
            new Route(POST, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/update/{resourceId}")
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

        return getResource(source, client);

    }

    private RestChannelConsumer getResource(Map<String, Object> source, NodeClient client) throws IOException {
        String name = (String) source.get("name");
        String description = source.containsKey("description") ? (String) source.get("description") : null;
        Map<String, String> attributes = source.containsKey("attributes") ? (Map<String, String>) source.get("attributes") : null;
        SampleResource resource = new SampleResource();
        resource.setName(name);
        resource.setDescription(description);
        resource.setAttributes(attributes);
        final GetResourceRequest createSampleResourceRequest = new GetResourceRequest(resource);
        return channel -> client.executeLocally(
            GetResourceAction.INSTANCE,
            createSampleResourceRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
