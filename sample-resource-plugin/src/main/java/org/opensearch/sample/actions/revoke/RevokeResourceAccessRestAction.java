/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.revoke;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.opensearch.accesscontrol.resources.EntityType;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.GET;

public class RevokeResourceAccessRestAction extends BaseRestHandler {

    public RevokeResourceAccessRestAction() {}

    @Override
    public List<Route> routes() {
        return singletonList(new Route(GET, "/_plugins/sample_resource_sharing/revoke"));
    }

    @Override
    public String getName() {
        return "revoke_sample_resources_access";
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        String resourceId = (String) source.get("resource_id");
        Map<EntityType, List<String>> revoke = (Map<EntityType, List<String>>) source.get("revoke");
        final RevokeResourceAccessRequest revokeResourceAccessRequest = new RevokeResourceAccessRequest(resourceId, revoke);
        return channel -> client.executeLocally(
            RevokeResourceAccessAction.INSTANCE,
            revokeResourceAccessRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
