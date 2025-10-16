/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.delete;

import java.util.List;

import org.opensearch.core.common.Strings;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.transport.client.node.NodeClient;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.DELETE;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_API_PREFIX;

/**
 * Rest Action to delete a Sample Resource.
 */
public class DeleteResourceGroupRestAction extends BaseRestHandler {

    public DeleteResourceGroupRestAction() {}

    @Override
    public List<Route> routes() {
        return singletonList(new Route(DELETE, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/group/delete/{resource_id}"));
    }

    @Override
    public String getName() {
        return "delete_sample_resource_group";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String resourceId = request.param("resource_id");
        if (Strings.isNullOrEmpty(resourceId)) {
            throw new IllegalArgumentException("resource_id parameter is required");
        }
        final DeleteResourceGroupRequest createSampleResourceRequest = new DeleteResourceGroupRequest(resourceId);
        return channel -> client.executeLocally(
            DeleteResourceGroupAction.INSTANCE,
            createSampleResourceRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
