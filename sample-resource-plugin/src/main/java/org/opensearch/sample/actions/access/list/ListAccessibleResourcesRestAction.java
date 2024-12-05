/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.access.list;

import java.util.List;

import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.GET;

public class ListAccessibleResourcesRestAction extends BaseRestHandler {

    public ListAccessibleResourcesRestAction() {}

    @Override
    public List<Route> routes() {
        return singletonList(new Route(GET, "/_plugins/sample_resource_sharing/resource"));
    }

    @Override
    public String getName() {
        return "list_sample_resources";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        final ListAccessibleResourcesRequest listAccessibleResourcesRequest = new ListAccessibleResourcesRequest();
        return channel -> client.executeLocally(
            ListAccessibleResourcesAction.INSTANCE,
            listAccessibleResourcesRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
