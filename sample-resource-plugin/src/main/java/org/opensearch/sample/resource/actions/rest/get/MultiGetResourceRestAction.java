/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.get;

import java.util.List;

import org.opensearch.core.common.Strings;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_API_PREFIX;

/**
 * Rest action to get several sample resources in one request, given a comma-separated list of ids
 */
public class MultiGetResourceRestAction extends BaseRestHandler {

    public MultiGetResourceRestAction() {}

    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/mget/{resource_ids}"));
    }

    @Override
    public String getName() {
        return "multi_get_sample_resource";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        List<String> resourceIds = List.of(Strings.splitStringByCommaToArray(request.param("resource_ids")));

        final MultiGetResourceRequest multiGetResourceRequest = new MultiGetResourceRequest(resourceIds);
        return channel -> client.executeLocally(
            MultiGetResourceAction.INSTANCE,
            multiGetResourceRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
