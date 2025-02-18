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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.resources.RecipientType;
import org.opensearch.security.resources.RecipientTypeRegistry;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.resources.ResourceSharing;
import org.opensearch.security.resources.ShareWith;
import org.opensearch.security.spi.resources.Resource;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.api.Responses.badRequest;
import static org.opensearch.security.dlic.rest.api.Responses.forbidden;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.unauthorized;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_RESOURCE_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * This class handles the REST API for resource access management.
 */
public class ResourceAccessRestAction extends BaseRestHandler {
    private static final Logger LOGGER = LogManager.getLogger(ResourceAccessRestAction.class);

    private final ResourceAccessHandler resourceAccessHandler;

    public ResourceAccessRestAction(ResourceAccessHandler resourceAccessHandler) {
        this.resourceAccessHandler = resourceAccessHandler;
    }

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
        return "resource_api_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        consumeParams(request); // early consume params to avoid 400s
        String path = request.path().split(PLUGIN_RESOURCE_ROUTE_PREFIX)[1].split("/")[1];
        return switch (path) {
            case "list" -> channel -> handleListResources(request, channel);
            case "revoke" -> channel -> handleRevokeResource(request, channel);
            case "share" -> channel -> handleShareResource(request, channel);
            case "verify_access" -> channel -> handleVerifyRequest(request, channel);
            default -> channel -> badRequest(channel, "Unknown route: " + path);
        };
    }

    /**
     * Consume params early to avoid 400s.
     * @param request from which the params must be consumed
     */
    private void consumeParams(RestRequest request) {
        request.param("resourceIndex", "");
    }

    /**
     * Handle the list resources request.
     * @param request the request to handle
     * @param channel the channel to send the response to
     */
    private void handleListResources(RestRequest request, RestChannel channel) {
        String resourceIndex = request.param("resourceIndex", "");
        resourceAccessHandler.getAccessibleResourcesForCurrentUser(
            resourceIndex,
            ActionListener.wrap(resources -> sendResponse(channel, resources), e -> handleError(channel, e.getMessage(), e))
        );
    }

    /**
     * Handle the share resource request.
     * @param request the request to handle
     * @param channel the channel to send the response to
     * @throws IOException if an I/O error occurs
     */
    private void handleShareResource(RestRequest request, RestChannel channel) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }
        String resourceId = (String) source.get("resource_id");
        String resourceIndex = (String) source.get("resource_index");

        ShareWith shareWith = parseShareWith(source);
        resourceAccessHandler.shareWith(
            resourceId,
            resourceIndex,
            shareWith,
            ActionListener.wrap(response -> sendResponse(channel, response), e -> handleError(channel, e.getMessage(), e))
        );
    }

    /**
     * Handle the revoke resource request.
     * @param request the request to handle
     * @param channel the channel to send the response to
     * @throws IOException if an I/O error occurs
     */
    @SuppressWarnings("unchecked")
    private void handleRevokeResource(RestRequest request, RestChannel channel) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        String resourceId = (String) source.get("resource_id");
        String resourceIndex = (String) source.get("resource_index");

        Map<String, Set<String>> revokeSource = (Map<String, Set<String>>) source.get("entities");
        Map<RecipientType, Set<String>> revoke = revokeSource.entrySet()
            .stream()
            .collect(Collectors.toMap(entry -> RecipientTypeRegistry.fromValue(entry.getKey()), Map.Entry::getValue));
        Set<String> scopes = new HashSet<>(source.containsKey("scopes") ? (List<String>) source.get("scopes") : List.of());
        resourceAccessHandler.revokeAccess(
            resourceId,
            resourceIndex,
            revoke,
            scopes,
            ActionListener.wrap(response -> sendResponse(channel, response), e -> handleError(channel, e.getMessage(), e))
        );
    }

    /**
     * Handle the verify request.
     * @param request the request to handle
     * @param channel the channel to send the response to
     * @throws IOException if an I/O error occurs
     */
    private void handleVerifyRequest(RestRequest request, RestChannel channel) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        String resourceId = (String) source.get("resource_id");
        String resourceIndex = (String) source.get("resource_index");
        String scope = (String) source.get("scope");

        resourceAccessHandler.hasPermission(
            resourceId,
            resourceIndex,
            scope,
            ActionListener.wrap(response -> sendResponse(channel, response), e -> handleError(channel, e.getMessage(), e))
        );
    }

    /**
     * Parse the share with structure from the request body.
     * @param source the request body
     * @return the parsed ShareWith object
     * @throws IOException if an I/O error occurs
     */
    @SuppressWarnings("unchecked")
    private ShareWith parseShareWith(Map<String, Object> source) throws IOException {
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

    /**
     * Send the appropriate response to the channel.
     * @param channel the channel to send the response to
     * @param response the response to send
     * @throws IOException if an I/O error occurs
     */
    @SuppressWarnings("unchecked")
    private void sendResponse(RestChannel channel, Object response) throws IOException {
        if (response instanceof Set) { // list
            Set<Resource> resources = (Set<Resource>) response;
            ok(channel, (builder, params) -> builder.startObject().field("resources", resources).endObject());
        } else if (response instanceof ResourceSharing resourceSharing) { // share & revoke
            ok(channel, (resourceSharing::toXContent));
        } else if (response instanceof Boolean) { // verify_access
            ok(channel, (builder, params) -> builder.startObject().field("has_permission", String.valueOf(response)).endObject());
        }
    }

    /**
     * Handle errors that occur during request processing.
     * @param channel the channel to send the error response to
     * @param message the error message
     * @param e the exception that caused the error
     */
    private void handleError(RestChannel channel, String message, Exception e) {
        LOGGER.error(message, e);
        if (message.contains("not authorized")) {
            forbidden(channel, message);
        } else if (message.contains("no authenticated")) {
            unauthorized(channel);
        }
        channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, message));
    }
}
