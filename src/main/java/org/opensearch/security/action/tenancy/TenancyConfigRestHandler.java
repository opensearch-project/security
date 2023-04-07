/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.action.tenancy;

import java.io.IOException;
import java.util.List;

import com.google.common.collect.ImmutableList;

import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.PUT;

public class TenancyConfigRestHandler extends BaseRestHandler {

    public TenancyConfigRestHandler() {
        super();
    }

    @Override
    public String getName() {
        return "Multi Tenancy actions to Retrieve / Update configs.";
    }

    @Override
    public List<Route> routes() {
        return ImmutableList.of(
                new Route(GET, "/_plugins/_security/api/tenancy/config"),
                new Route(PUT, "/_plugins/_security/api/tenancy/config")
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient nodeClient) throws IOException {

        switch (request.method()) {
            case GET:
                return channel -> nodeClient.execute(
                        TenancyConfigRetrieveActions.INSTANCE,
                        new EmptyRequest(),
                        new RestToXContentListener<>(channel));
            case PUT:
                return channel -> nodeClient.execute(
                        TenancyConfigUpdateAction.INSTANCE,
                        TenancyConfigUpdateRequest.fromXContent(request.contentParser()),
                        new RestToXContentListener<>(channel));
            default:
                throw new RuntimeException("Not implemented");
        }
    }

}
