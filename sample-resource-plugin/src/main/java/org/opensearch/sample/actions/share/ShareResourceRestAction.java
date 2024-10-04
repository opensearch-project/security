/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.share;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.opensearch.accesscontrol.resources.ShareWith;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.GET;

public class ShareResourceRestAction extends BaseRestHandler {

    public ShareResourceRestAction() {}

    @Override
    public List<Route> routes() {
        return singletonList(new Route(GET, "/_plugins/sample_resource_sharing/share/{resource_id}"));
    }

    @Override
    public String getName() {
        return "list_sample_resources";
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        String resourceId = (String) source.get("resource_id");
        ShareWith shareWith = (ShareWith) source.get("share_with");
        final ShareResourceRequest shareResourceRequest = new ShareResourceRequest(resourceId, shareWith);
        return channel -> client.executeLocally(ShareResourceAction.INSTANCE, shareResourceRequest, new RestToXContentListener<>(channel));
    }
}
