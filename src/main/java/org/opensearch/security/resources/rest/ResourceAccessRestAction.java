/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.api.Responses.badRequest;
import static org.opensearch.security.dlic.rest.api.Responses.forbidden;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.unauthorized;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_RESOURCE_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static org.opensearch.security.resources.rest.ResourceAccessRequest.Operation.LIST;
import static org.opensearch.security.resources.rest.ResourceAccessRequest.Operation.REVOKE;
import static org.opensearch.security.resources.rest.ResourceAccessRequest.Operation.SHARE;
import static org.opensearch.security.resources.rest.ResourceAccessRequest.Operation.VERIFY;

/**
 * This class handles the REST API for resource access management.
 * It provides endpoints for listing, revoking, sharing, and verifying resource access.
 *
 * @opensearch.experimental
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

        ResourceAccessRequest resourceAccessRequest = ResourceAccessRequest.from(source, request.params());
        return channel -> {
            client.executeLocally(ResourceAccessAction.INSTANCE, resourceAccessRequest, new ActionListener<>() {

                @Override
                public void onResponse(ResourceAccessResponse response) {
                    try {
                        sendResponse(channel, response);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    handleError(channel, e);
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

    /**
     * Send the appropriate response to the channel.
     * @param channel the channel to send the response to
     * @param response the response to send
     * @throws IOException if an I/O error occurs
     */
    private void sendResponse(RestChannel channel, ResourceAccessResponse response) throws IOException {
        ok(channel, response::toXContent);
    }

    /**
     * Handle errors that occur during request processing.
     * @param channel the channel to send the error response to
     * @param e the exception that caused the error
     */
    private void handleError(RestChannel channel, Exception e) {
        String message = e.getMessage();
        LOGGER.error(message, e);
        if (message.contains("not authorized")) {
            forbidden(channel, message);
        } else if (message.contains("no authenticated")) {
            unauthorized(channel);
        } else if (message.contains("not a system index")) {
            badRequest(channel, message);
        }
        channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, message));
    }
}
