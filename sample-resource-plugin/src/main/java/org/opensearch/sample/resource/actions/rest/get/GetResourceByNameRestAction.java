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
 * Rest action to get a sample resource by its name
 */
public class GetResourceByNameRestAction extends BaseRestHandler {

    public GetResourceByNameRestAction() {}

    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/get_by_name/{resource_name}"));
    }

    @Override
    public String getName() {
        return "get_sample_resource_by_name";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String resourceName = request.param("resource_name");

        final GetResourceByNameRequest getResourceByNameRequest = new GetResourceByNameRequest(resourceName);
        return channel -> client.executeLocally(
            GetResourceByNameAction.INSTANCE,
            getResourceByNameRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
