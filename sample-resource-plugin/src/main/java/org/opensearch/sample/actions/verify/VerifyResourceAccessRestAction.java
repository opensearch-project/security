/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.verify;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.POST;

public class VerifyResourceAccessRestAction extends BaseRestHandler {

    public VerifyResourceAccessRestAction() {}

    @Override
    public List<Route> routes() {
        return singletonList(new Route(POST, "/_plugins/sample_resource_sharing/verify_resource_access"));
    }

    @Override
    public String getName() {
        return "verify_resource_access";
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        Map<String, Object> source;
        try (XContentParser parser = request.contentParser()) {
            source = parser.map();
        }

        String resourceIdx = (String) source.get("resource_idx");
        String sourceIdx = (String) source.get("source_idx");
        String scope = (String) source.get("scope");

        // final CreateResourceRequest<SampleResource> createSampleResourceRequest = new CreateResourceRequest<>(resource);
        return channel -> client.executeLocally(VerifyResourceAccessAction.INSTANCE, null, new RestToXContentListener<>(channel));
    }
}
