/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.rest.resources.access.list;

import java.io.IOException;
import java.util.List;

import com.google.common.collect.ImmutableList;

import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class RestListAccessibleResourcesAction extends BaseRestHandler {

    public RestListAccessibleResourcesAction() {}

    @Override
    public List<Route> routes() {
        return addRoutesPrefix(ImmutableList.of(new Route(GET, "/resources/list/{resourceIndex}")), PLUGIN_ROUTE_PREFIX);
    }

    @Override
    public String getName() {
        return "list_accessible_resources";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String resourceIndex = request.param("resourceIndex", "");
        final ListAccessibleResourcesRequest listAccessibleResourcesRequest = new ListAccessibleResourcesRequest(resourceIndex);
        return channel -> client.executeLocally(
            ListAccessibleResourcesAction.INSTANCE,
            listAccessibleResourcesRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
