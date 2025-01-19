/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.rest.resources.access;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;

import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.security.resources.RecipientType;
import org.opensearch.security.resources.RecipientTypeRegistry;
import org.opensearch.security.resources.ShareWith;
import org.opensearch.security.rest.resources.access.list.ListAccessibleResourcesAction;
import org.opensearch.security.rest.resources.access.list.ListAccessibleResourcesRequest;
import org.opensearch.security.rest.resources.access.revoke.RevokeResourceAccessAction;
import org.opensearch.security.rest.resources.access.revoke.RevokeResourceAccessRequest;
import org.opensearch.security.rest.resources.access.share.ShareResourceAction;
import org.opensearch.security.rest.resources.access.share.ShareResourceRequest;
import org.opensearch.security.rest.resources.access.verify.VerifyResourceAccessAction;
import org.opensearch.security.rest.resources.access.verify.VerifyResourceAccessRequest;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.api.Responses.badRequest;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_RESOURCE_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class RestResourceAccessAction extends BaseRestHandler {

    public RestResourceAccessAction() {}

    @Override
    public List<Route> routes() {
        return addRoutesPrefix(
            ImmutableList.of(
                new Route(GET, "/list/{resourceIndex}"),
                new Route(POST, "/revoke"),
                new Route(POST, "/share"),
                new Route(POST, "/verify_access")
            ),
            PLUGIN_RESOURCE_ROUTE_PREFIX
        );
    }

    @Override
    public String getName() {
        return "resource_access_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        consumeParams(request); // to avoid 400s
        String path = request.path().split(PLUGIN_RESOURCE_ROUTE_PREFIX)[1].split("/")[1];
        return switch (path) {
            case "list" -> channel -> handleListRequest(request, client, channel);
            case "revoke" -> channel -> handleRevokeRequest(request, client, channel);
            case "share" -> channel -> handleShareRequest(request, client, channel);
            case "verify_access" -> channel -> handleVerifyRequest(request, client, channel);
            default -> channel -> badRequest(channel, "Unknown route: " + path);
        };
    }

    private void consumeParams(RestRequest request) {
        request.param("resourceIndex", "");
    }

    public void handleListRequest(RestRequest request, NodeClient client, RestChannel channel) {
        String resourceIndex = request.param("resourceIndex", "");
        final ListAccessibleResourcesRequest listAccessibleResourcesRequest = new ListAccessibleResourcesRequest(resourceIndex);
        client.executeLocally(
            ListAccessibleResourcesAction.INSTANCE,
            listAccessibleResourcesRequest,
            new RestToXContentListener<>(channel)
        );

    }

    public void handleRevokeRequest(RestRequest request, NodeClient client, RestChannel channel) throws IOException {
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
        client.executeLocally(RevokeResourceAccessAction.INSTANCE, revokeResourceAccessRequest, new RestToXContentListener<>(channel));
    }

    public void handleShareRequest(RestRequest request, NodeClient client, RestChannel channel) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        String resourceId = (String) source.get("resource_id");
        String resourceIndex = (String) source.get("resource_index");

        ShareWith shareWith = parseShareWith(source);
        final ShareResourceRequest shareResourceRequest = new ShareResourceRequest(resourceId, resourceIndex, shareWith);
        client.executeLocally(ShareResourceAction.INSTANCE, shareResourceRequest, new RestToXContentListener<>(channel));
    }

    public void handleVerifyRequest(RestRequest request, NodeClient client, RestChannel channel) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        String resourceId = (String) source.get("resource_id");
        String resourceIndex = (String) source.get("resource_index");
        String scope = (String) source.get("scope");

        final VerifyResourceAccessRequest verifyResourceAccessRequest = new VerifyResourceAccessRequest(resourceId, resourceIndex, scope);
        client.executeLocally(VerifyResourceAccessAction.INSTANCE, verifyResourceAccessRequest, new RestToXContentListener<>(channel));
    }

    private ShareWith parseShareWith(Map<String, Object> source) throws IOException {
        @SuppressWarnings("unchecked")
        Map<String, Object> shareWithMap = (Map<String, Object>) source.get("share_with");
        if (shareWithMap == null || shareWithMap.isEmpty()) {
            throw new IllegalArgumentException("share_with is required and cannot be empty");
        }

        String jsonString = XContentFactory.jsonBuilder().map(shareWithMap).toString();

        try (
            XContentParser parser = XContentType.JSON.xContent()
                .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, jsonString)
        ) {
            return ShareWith.fromXContent(parser);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid share_with structure: " + e.getMessage(), e);
        }
    }
}
