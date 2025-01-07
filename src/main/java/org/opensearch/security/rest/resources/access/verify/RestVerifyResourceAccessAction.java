/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.rest.resources.access.verify;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;

import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class RestVerifyResourceAccessAction extends BaseRestHandler {

    public RestVerifyResourceAccessAction() {}

    @Override
    public List<Route> routes() {
        return addRoutesPrefix(ImmutableList.of(new Route(GET, "/resources/verify_access")), PLUGIN_ROUTE_PREFIX);
    }

    @Override
    public String getName() {
        return "verify_resource_access";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        String resourceId = (String) source.get("resource_id");
        String resourceIndex = (String) source.get("resource_index");
        String scope = (String) source.get("scope");

        final VerifyResourceAccessRequest verifyResourceAccessRequest = new VerifyResourceAccessRequest(resourceId, resourceIndex, scope);
        return channel -> client.executeLocally(
            VerifyResourceAccessAction.INSTANCE,
            verifyResourceAccessRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
