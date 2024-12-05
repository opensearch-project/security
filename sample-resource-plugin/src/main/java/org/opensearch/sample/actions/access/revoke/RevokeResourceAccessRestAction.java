/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.access.revoke;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.opensearch.accesscontrol.resources.EntityType;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.POST;

public class RevokeResourceAccessRestAction extends BaseRestHandler {

    public RevokeResourceAccessRestAction() {}

    @Override
    public List<Route> routes() {
        return singletonList(new Route(POST, "/_plugins/sample_resource_sharing/revoke"));
    }

    @Override
    public String getName() {
        return "revoke_sample_resources_access";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        String resourceId = (String) source.get("resource_id");
        @SuppressWarnings("unchecked")
        Map<String, List<String>> revokeSource = (Map<String, List<String>>) source.get("entities");
        Map<EntityType, List<String>> revoke = revokeSource.entrySet().stream().collect(Collectors.toMap(entry -> {
            try {
                return EntityType.fromValue(entry.getKey());
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(
                    "Invalid entity type: " + entry.getKey() + ". Valid values are: " + Arrays.toString(EntityType.values())
                );
            }
        }, Map.Entry::getValue));
        @SuppressWarnings("unchecked")
        List<String> scopes = source.containsKey("scopes") ? (List<String>) source.get("scopes") : List.of();
        final RevokeResourceAccessRequest revokeResourceAccessRequest = new RevokeResourceAccessRequest(resourceId, revoke, scopes);
        return channel -> client.executeLocally(
            RevokeResourceAccessAction.INSTANCE,
            revokeResourceAccessRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
