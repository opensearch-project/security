/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.revoke;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.transport.client.node.NodeClient;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_API_PREFIX;

/**
 * Rest Action to revoke sample resource access
 */
public class RevokeResourceAccessRestAction extends BaseRestHandler {

    public RevokeResourceAccessRestAction() {}

    @Override
    public List<Route> routes() {
        return singletonList(new Route(POST, SAMPLE_RESOURCE_PLUGIN_API_PREFIX + "/revoke/{resource_id}"));
    }

    @Override
    public String getName() {
        return "revoke_sample_resource";
    }

    @SuppressWarnings("unchecked")
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String resourceId = request.param("resource_id");
        if (Strings.isNullOrEmpty(resourceId)) {
            throw new IllegalArgumentException("resource_id parameter is required");
        }
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        final RevokeResourceAccessRequest getResourceRequest = new RevokeResourceAccessRequest(
            resourceId,
            (Map<String, Object>) source.get("entities_to_revoke")
        );
        return channel -> client.executeLocally(
            RevokeResourceAccessAction.INSTANCE,
            getResourceRequest,
            new RestToXContentListener<>(channel)
        );
    }
}
