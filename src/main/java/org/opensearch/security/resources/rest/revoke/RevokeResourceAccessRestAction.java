/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest.revoke;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_RESOURCE_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * This class implements the revoke REST API for resource access management.
 * It provides endpoints for revoking resource access.
 *
 * @opensearch.experimental
 */
public class RevokeResourceAccessRestAction extends BaseRestHandler {
    private static final Logger LOGGER = LogManager.getLogger(RevokeResourceAccessRestAction.class);

    public RevokeResourceAccessRestAction() {}

    @Override
    public List<Route> routes() {
        return addRoutesPrefix(ImmutableList.of(new Route(POST, "/revoke")), PLUGIN_RESOURCE_ROUTE_PREFIX);
    }

    @Override
    public String getName() {
        return "revoke_resource_access_api_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        Map<String, Object> source = new HashMap<>();
        if (request.hasContent()) {
            try (XContentParser parser = request.contentParser()) {
                source = parser.map();
            }
        }

        RevokeResourceAccessRequest resourceAccessRequest = RevokeResourceAccessRequest.from(source, request.params());
        return channel -> {
            client.executeLocally(RevokeResourceAccessAction.INSTANCE, resourceAccessRequest, new ActionListener<>() {

                @Override
                public void onResponse(RevokeResourceAccessResponse response) {
                    try {
                        sendResponse(channel, response);
                    } catch (IOException e) {
                        LOGGER.error(e.getMessage(), e);
                        handleError(channel, e);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    LOGGER.debug(e.getMessage(), e);
                    handleError(channel, e);
                }

            });
        };
    }

    /**
     * Send the appropriate response to the channel.
     * @param channel the channel to send the response to
     * @param response the response to send
     * @throws IOException if an I/O error occurs
     */
    private void sendResponse(RestChannel channel, RevokeResourceAccessResponse response) throws IOException {
        ok(channel, response::toXContent);
    }

    /**
     * Handle errors that occur during request processing.
     * @param channel the channel to send the error response to
     * @param e the exception that caused the error
     */
    private void handleError(RestChannel channel, Exception e) {
        String message = e.getMessage();
        if (e instanceof OpenSearchStatusException ex) {
            response(channel, ex.status(), message);
        } else {
            channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, message));
        }
    }
}
