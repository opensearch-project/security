/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.api.share;

import java.io.IOException;
import java.util.List;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.PATCH;
import static org.opensearch.rest.RestRequest.Method.PUT;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_API_RESOURCE_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * This class implements the share REST API for resource access management.
 * It provides endpoints for sharing a resource.
 *
 */
public class ShareRestAction extends BaseRestHandler {
    private static final Logger LOGGER = LogManager.getLogger(ShareRestAction.class);

    private final ResourcePluginInfo resourcePluginInfo;

    public ShareRestAction(ResourcePluginInfo resourcePluginInfo) {
        this.resourcePluginInfo = resourcePluginInfo;
    }

    @Override
    public List<Route> routes() {
        return addRoutesPrefix(
            ImmutableList.of(new Route(PUT, "/share"), new Route(GET, "/share"), new Route(PATCH, "/share")),
            PLUGIN_API_RESOURCE_ROUTE_PREFIX
        );
    }

    @Override
    public String getName() {
        return getClass().getName();
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        // These two params will only be present with GET request
        String resourceId = request.param("resource_id");
        String resourceType = request.param("resource_type");

        String resourceIndex = resourcePluginInfo.indexByType(resourceType);

        ShareRequest.Builder builder = new ShareRequest.Builder();
        builder.method(request.method());

        if (resourceIndex != null) {
            builder.resourceIndex(resourceIndex);
            builder.resourceType(resourceType);
        }
        if (resourceId != null) {
            builder.resourceId(resourceId);
        }

        if (request.hasContent()) {
            builder.parseContent(request.contentParser(), resourcePluginInfo);
        }

        ShareRequest shareRequest = builder.build();

        return channel -> {
            client.executeLocally(
                ShareAction.INSTANCE,
                shareRequest,
                ActionListener.wrap(resp -> ok(channel, resp::toXContent), e -> handleError(channel, e))
            );
        };
    }

    private void handleError(RestChannel channel, Exception e) {
        LOGGER.error("Error while processing request", e);
        String message = e.getMessage();
        if (e instanceof OpenSearchStatusException ex) {
            response(channel, ex.status(), message);
        } else {
            channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, message));
        }
    }
}
