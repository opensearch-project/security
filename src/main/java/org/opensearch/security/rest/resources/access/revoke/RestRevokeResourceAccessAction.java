/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.rest.resources.access.revoke;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;

import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.security.resources.RecipientType;
import org.opensearch.security.resources.RecipientTypeRegistry;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class RestRevokeResourceAccessAction extends BaseRestHandler {

    public RestRevokeResourceAccessAction() {}

    @Override
    public List<Route> routes() {
        return addRoutesPrefix(ImmutableList.of(new Route(POST, "/resources/revoke")), PLUGIN_ROUTE_PREFIX);
    }

    @Override
    public String getName() {
        return "revoke_resources_access";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        String resourceId = (String) source.get("resource_id");
        String resourceIndex = (String) source.get("resource_index");
        @SuppressWarnings("unchecked")
        Map<String, Set<String>> revokeSource = (Map<String, Set<String>>) source.get("entities");
        Map<RecipientType, Set<String>> revoke = revokeSource.entrySet()
            .stream()
            .collect(Collectors.toMap(entry -> RecipientTypeRegistry.fromValue(entry.getKey()), Map.Entry::getValue));
        @SuppressWarnings("unchecked")
        Set<String> scopes = new HashSet<>(source.containsKey("scopes") ? (List<String>) source.get("scopes") : List.of());
        final RevokeResourceAccessRequest revokeResourceAccessRequest = new RevokeResourceAccessRequest(
            resourceId,
            resourceIndex,
            revoke,
            scopes
        );
        return channel -> client.executeLocally(
            RevokeResourceAccessAction.INSTANCE,
            revokeResourceAccessRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
