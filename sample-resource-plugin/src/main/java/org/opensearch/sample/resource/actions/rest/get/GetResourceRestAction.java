/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.get;

import java.util.List;

import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_API_PREFIX;

/**
 * Rest action to get a sample resource
 */
public class GetResourceRestAction extends BaseRestHandler {

    public GetResourceRestAction() {}

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(GET, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/get/{resource_id}"),
            new Route(GET, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/get")
        );
    }

    @Override
    public String getName() {
        return "get_sample_resource";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String resourceId = request.param("resource_id");

        final GetResourceRequest getResourceRequest = new GetResourceRequest(resourceId);
        return channel -> client.executeLocally(GetResourceAction.INSTANCE, getResourceRequest, new RestToXContentListener<>(channel));
    }
}
