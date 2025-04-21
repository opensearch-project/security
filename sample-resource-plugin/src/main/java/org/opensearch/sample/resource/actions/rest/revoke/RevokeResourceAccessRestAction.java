/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.revoke;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.SharedWithActionGroup;
import org.opensearch.transport.client.node.NodeClient;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_API_PREFIX;

/**
 * Rest Action to revoke sample resource access
 */
public class RevokeResourceAccessRestAction extends BaseRestHandler {

    public RevokeResourceAccessRestAction() {}

    @Override
    public List<Route> routes() {
        return singletonList(new Route(POST, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/revoke/{resource_id}"));
    }

    @Override
    public String getName() {
        return "revoke_sample_resource";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String resourceId = request.param("resource_id");
        if (Strings.isNullOrEmpty(resourceId)) {
            throw new IllegalArgumentException("resource_id parameter is required");
        }
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        final RevokeResourceAccessRequest revokeResourceAccessRequest = new RevokeResourceAccessRequest(
            resourceId,
            parseRevokedEntities((Map<String, Object>) source.get("entities_to_revoke"))
        );
        return channel -> client.executeLocally(
            RevokeResourceAccessAction.INSTANCE,
            revokeResourceAccessRequest,
            new RestToXContentListener<>(channel)
        );
    }

    private SharedWithActionGroup.ActionGroupRecipients parseRevokedEntities(Map<String, Object> source) {
        if (source == null || source.isEmpty()) {
            throw new IllegalArgumentException("entities_to_revoke is required and cannot be empty");
        }

        Map<Recipient, Set<String>> entitiesToRevoke = source.entrySet()
            .stream()
            .filter(entry -> entry.getValue() instanceof Collection<?>)
            .collect(
                Collectors.toMap(
                    entry -> Recipient.fromValue(entry.getKey()),
                    entry -> ((Collection<?>) entry.getValue()).stream()
                        .filter(String.class::isInstance)
                        .map(String.class::cast)
                        .collect(Collectors.toSet())
                )
            );

        return new SharedWithActionGroup.ActionGroupRecipients(entitiesToRevoke);
    }
}
