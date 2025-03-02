/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.common.resources.rest;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.common.dlic.rest.api.Responses.badRequest;
import static org.opensearch.security.common.resources.rest.ResourceAccessRequest.Operation.LIST;
import static org.opensearch.security.common.resources.rest.ResourceAccessRequest.Operation.REVOKE;
import static org.opensearch.security.common.resources.rest.ResourceAccessRequest.Operation.SHARE;
import static org.opensearch.security.common.resources.rest.ResourceAccessRequest.Operation.VERIFY;
import static org.opensearch.security.common.support.Utils.PLUGIN_RESOURCE_ROUTE_PREFIX;
import static org.opensearch.security.common.support.Utils.addRoutesPrefix;

/**
 * This class handles the REST API for resource access management.
 */
public class ResourceAccessRestAction extends BaseRestHandler {
    private static final Logger LOGGER = LogManager.getLogger(ResourceAccessRestAction.class);

    public ResourceAccessRestAction() {}

    @Override
    public List<Route> routes() {
        return addRoutesPrefix(
            ImmutableList.of(
                new Route(GET, "/list/{resource_index}"),
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

        Map<String, Object> source = new HashMap<>();
        if (request.hasContent()) {
            try (XContentParser parser = request.contentParser()) {
                source = parser.map();
            }
        }

        String path = request.path().split(PLUGIN_RESOURCE_ROUTE_PREFIX)[1].split("/")[1];
        switch (path) {
            case "list" -> source.put("operation", LIST);
            case "revoke" -> source.put("operation", REVOKE);
            case "share" -> source.put("operation", SHARE);
            case "verify_access" -> source.put("operation", VERIFY);
            default -> {
                return channel -> badRequest(channel, "Unknown route: " + path);
            }
        }

        ResourceAccessRequest resourceAccessRequest = new ResourceAccessRequest(source, request.params());
        return channel -> {
            client.executeLocally(ResourceAccessAction.INSTANCE, resourceAccessRequest, new RestToXContentListener<>(channel) {
                @Override
                public RestResponse buildResponse(ResourceAccessResponse response, XContentBuilder builder) throws Exception {
                    assert !response.isFragment(); // would be nice if we could make default methods final
                    response.toXContent(builder, channel.request());
                    return new BytesRestResponse(getStatus(response), builder);
                }

                @Override
                protected RestStatus getStatus(ResourceAccessResponse response) {
                    return RestStatus.OK;
                }

            });
        };
    }

    /**
     * Consume params early to avoid 400s.
     *
     * @param request from which the params must be consumed
     */
    private void consumeParams(RestRequest request) {
        request.param("resource_index", "");
    }

    // /**
    // * Send the appropriate response to the channel.
    // * @param channel the channel to send the response to
    // * @param response the response to send
    // * @throws IOException if an I/O error occurs
    // */
    // @SuppressWarnings("unchecked")
    // private void sendResponse(RestChannel channel, Object response) throws IOException {
    // if (response instanceof Set) { // get
    // Set<Resource> resources = (Set<Resource>) response;
    // ok(channel, (builder, params) -> builder.startObject().field("resources", resources).endObject());
    // } else if (response instanceof ResourceSharing resourceSharing) { // share & revoke
    // ok(channel, (resourceSharing::toXContent));
    // } else if (response instanceof Boolean) { // verify_access
    // ok(channel, (builder, params) -> builder.startObject().field("has_permission", String.valueOf(response)).endObject());
    // }
    // }
    //
    // /**
    // * Handle errors that occur during request processing.
    // * @param channel the channel to send the error response to
    // * @param message the error message
    // * @param e the exception that caused the error
    // */
    // private void handleError(RestChannel channel, String message, Exception e) {
    // LOGGER.error(message, e);
    // if (message.contains("not authorized")) {
    // forbidden(channel, message);
    // } else if (message.contains("no authenticated")) {
    // unauthorized(channel);
    // }
    // channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, message));
    // }
}
