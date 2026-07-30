/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.api.access;

import java.io.IOException;
import java.util.List;

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
import org.opensearch.security.resources.ResolvedResourceAccess;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_API_RESOURCE_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * Returns resolved access information for the current user on a single resource.
 */
public class ResourceAccessRestAction extends BaseRestHandler {
    private static final Logger LOGGER = LogManager.getLogger(ResourceAccessRestAction.class);

    private final ResourceAccessHandler resourceAccessHandler;
    private final ResourcePluginInfo resourcePluginInfo;
    private final OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting;
    private final OpensearchDynamicSetting<List<String>> resourceSharingProtectedTypesSetting;

    public ResourceAccessRestAction(
        ResourceAccessHandler resourceAccessHandler,
        ResourcePluginInfo resourcePluginInfo,
        OpensearchDynamicSetting<Boolean> resourceSharingEnabledSetting,
        OpensearchDynamicSetting<List<String>> resourceSharingProtectedTypesSetting
    ) {
        this.resourceAccessHandler = resourceAccessHandler;
        this.resourcePluginInfo = resourcePluginInfo;
        this.resourceSharingEnabledSetting = resourceSharingEnabledSetting;
        this.resourceSharingProtectedTypesSetting = resourceSharingProtectedTypesSetting;
    }

    @Override
    public List<Route> routes() {
        return addRoutesPrefix(ImmutableList.of(new Route(GET, "/access")), PLUGIN_API_RESOURCE_ROUTE_PREFIX);
    }

    @Override
    public String getName() {
        return getClass().getName();
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        if (!resourceSharingEnabledSetting.getDynamicSettingValue()) {
            return channel -> { channel.sendResponse(new BytesRestResponse(RestStatus.NOT_IMPLEMENTED, "Feature disabled.")); };
        }

        final String resourceType = request.param("resource_type");
        final String resourceId = request.param("resource_id");

        if (resourceType == null || resourceId == null) {
            return channel -> {
                channel.sendResponse(new BytesRestResponse(RestStatus.BAD_REQUEST, "resource_type and resource_id are required"));
            };
        }

        final String resourceIndex = resourcePluginInfo.indexByType(resourceType);

        if (resourceIndex == null) {
            return channel -> {
                String message = String.format(
                    "Invalid resource type: %s. Must be one of: %s",
                    resourceType,
                    resourceSharingProtectedTypesSetting.getDynamicSettingValue()
                );
                channel.sendResponse(new BytesRestResponse(RestStatus.BAD_REQUEST, message));
            };
        }

        return channel -> resourceAccessHandler.resolveAccessForCurrentUser(
            resourceId,
            resourceType,
            ActionListener.wrap(accessInfo -> handleResponse(channel, accessInfo), e -> handleError(channel, e))
        );
    }

    private void handleResponse(RestChannel channel, ResolvedResourceAccess accessInfo) {
        try (XContentBuilder builder = channel.newBuilder()) {
            builder.startObject();
            builder.field("access");
            accessInfo.toXContent(builder, ToXContent.EMPTY_PARAMS);
            builder.endObject();
            channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));
        } catch (IOException ioe) {
            handleError(channel, ioe);
        }
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
