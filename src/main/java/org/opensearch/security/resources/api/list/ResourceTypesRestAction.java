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
import java.util.Set;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_API_RESOURCE_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * This class implements the list REST API to list registered resource types.
 */
public class ResourceTypesRestAction extends BaseRestHandler {
    private static final Logger LOGGER = LogManager.getLogger(ResourceTypesRestAction.class);

    private final Set<ResourcePluginInfo.ResourceDashboardInfo> resourceTypes;

    public ResourceTypesRestAction(final ResourcePluginInfo resourcePluginInfo) {
        super();
        this.resourceTypes = resourcePluginInfo.getResourceTypes();
    }

    @Override
    public List<Route> routes() {
        return addRoutesPrefix(ImmutableList.of(new Route(GET, "/types")), PLUGIN_API_RESOURCE_ROUTE_PREFIX);
    }

    @Override
    public String getName() {
        return getClass().getName();
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return channel -> {
            try (XContentBuilder builder = channel.newBuilder()) { // NOSONAR
                builder.startObject();
                builder.startArray("types");
                for (var p : resourceTypes) {
                    p.toXContent(builder, ToXContent.EMPTY_PARAMS);
                }
                builder.endArray();
                builder.endObject();

                channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));
            } catch (Exception e) {
                handleErrorResponse(channel, e);
            }
        };
    }

    private void handleErrorResponse(RestChannel channel, Exception e) {
        LOGGER.error("Error while processing request", e);
        final String message = e.getMessage();
        if (e instanceof OpenSearchStatusException ex) {
            response(channel, ex.status(), message);
        } else {
            channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, message));
        }
    }

}
