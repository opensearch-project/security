/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.api.share;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.PATCH;
import static org.opensearch.rest.RestRequest.Method.PUT;
import static org.opensearch.security.dlic.rest.api.Responses.badRequest;
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

    private final static Set<String> allowedPatchOperations = Set.of("share_with", "revoke");

    public ShareRestAction() {}

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
        String resId = request.param("resource_id");
        String resourceIndex = request.param("resource_index");

        Map<String, Object> source = new HashMap<>();
        if (request.hasContent()) {
            try (XContentParser parser = request.contentParser()) {
                source = parser.map();
            }
        }

        if (!Strings.isNullOrEmpty(resId)) {
            source.put("resource_id", resId);
        }
        if (!Strings.isNullOrEmpty(resourceIndex)) {
            source.put("resource_index", resourceIndex);
        }

        source.put("method", request.method());

        ShareRequest sharingInfoUpdateRequest = ShareRequest.from(source);

        return channel -> {
            // TODO confirm the validation here for patch Operations
            Map<String, Object> patch = sharingInfoUpdateRequest.getPatch();
            if (patch != null && !allowedPatchOperations.containsAll(patch.keySet())) {
                badRequest(channel, "Invalid patch operation supplied. Allowed ops: " + allowedPatchOperations);
            }

            client.executeLocally(ShareAction.INSTANCE, sharingInfoUpdateRequest, new ActionListener<>() {

                @Override
                public void onResponse(ShareResponse response) {
                    ok(channel, response::toXContent);
                }

                @Override
                public void onFailure(Exception e) {
                    LOGGER.debug(e.getMessage(), e);
                    handleError(channel, e);
                }

            });
        };
    }

    private void handleError(RestChannel channel, Exception e) {
        String message = e.getMessage();
        if (e instanceof OpenSearchStatusException ex) {
            response(channel, ex.status(), message);
        } else {
            channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, message));
        }
    }
}
