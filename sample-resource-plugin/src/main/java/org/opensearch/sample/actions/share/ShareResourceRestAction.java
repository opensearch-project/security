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
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.POST;

public class ShareResourceRestAction extends BaseRestHandler {

    public ShareResourceRestAction() {}

    @Override
    public List<Route> routes() {
        return singletonList(new Route(POST, "/_plugins/sample_resource_sharing/share"));
    }

    @Override
    public String getName() {
        return "share_sample_resources";
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        String resourceId = (String) source.get("resource_id");

        ShareWith shareWith = parseShareWith(source);
        final ShareResourceRequest shareResourceRequest = new ShareResourceRequest(resourceId, shareWith);
        return channel -> client.executeLocally(ShareResourceAction.INSTANCE, shareResourceRequest, new RestToXContentListener<>(channel));
    }

    private ShareWith parseShareWith(Map<String, Object> source) throws IOException {
        @SuppressWarnings("unchecked")
        Map<String, Object> shareWithMap = (Map<String, Object>) source.get("share_with");
        if (shareWithMap == null || shareWithMap.isEmpty()) {
            throw new IllegalArgumentException("share_with is required and cannot be empty");
        }

        String jsonString = XContentFactory.jsonBuilder().map(shareWithMap).toString();

        try (
            XContentParser parser = XContentType.JSON.xContent()
                .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, jsonString)
        ) {
            return ShareWith.fromXContent(parser);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid share_with structure: " + e.getMessage(), e);
        }
    }
}
