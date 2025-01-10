/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.delete;

import java.util.List;

import org.opensearch.client.node.NodeClient;
import org.opensearch.core.common.Strings;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.DELETE;

public class DeleteResourceRestAction extends BaseRestHandler {

    public DeleteResourceRestAction() {}

    @Override
    public List<Route> routes() {
        return singletonList(new Route(DELETE, "/_plugins/sample_resource_sharing/delete/{resource_id}"));
    }

    @Override
    public String getName() {
        return "delete_sample_resource";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String resourceId = request.param("resource_id");
        if (Strings.isNullOrEmpty(resourceId)) {
            throw new IllegalArgumentException("resource_id parameter is required");
        }
        final DeleteResourceRequest createSampleResourceRequest = new DeleteResourceRequest(resourceId);
        return channel -> client.executeLocally(
            DeleteResourceAction.INSTANCE,
            createSampleResourceRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
