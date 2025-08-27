/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.api.list;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_API_RESOURCE_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * This class implements the list REST API to list accessible resources in a given resource type.
 */
public class AccessibleResourcesRestAction extends BaseRestHandler {
    private static final Logger LOGGER = LogManager.getLogger(AccessibleResourcesRestAction.class);

    private final ResourceAccessHandler resourceAccessHandler;

    public AccessibleResourcesRestAction(final ResourceAccessHandler resourceAccessHandler) {
        super();
        this.resourceAccessHandler = resourceAccessHandler;
    }

    @Override
    public List<Route> routes() {
        return addRoutesPrefix(ImmutableList.of(new Route(GET, "/list")), PLUGIN_API_RESOURCE_ROUTE_PREFIX);
    }

    @Override
    public String getName() {
        return getClass().getName();
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        final String resourceIndex = Objects.requireNonNull(request.param("resource_type"), "resource_type is required");

        return channel -> resourceAccessHandler.getResourceSharingInfoForCurrentUser(resourceIndex, ActionListener.wrap(rows -> {

            // TODO evaluate which user can share and which cannot

            try (XContentBuilder b = channel.newBuilder()) {
                b.startObject();
                b.startArray("resources");
                for (ResourceSharing row : rows) {
                    row.toXContent(b, ToXContent.EMPTY_PARAMS);
                }
                b.endArray();
                b.endObject();
                channel.sendResponse(new BytesRestResponse(RestStatus.OK, b));
            } catch (IOException ioe) {
                handleError(channel, ioe);
            }
        }, e -> handleError(channel, e)));
    }

    private void handleError(RestChannel channel, Exception e) {
        LOGGER.error("Error while processing request", e);
        final String message = e.getMessage();
        if (e instanceof OpenSearchStatusException ex) {
            response(channel, ex.status(), message);
        } else {
            channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, message));
        }
    }

}
