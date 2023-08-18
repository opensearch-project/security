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

package org.opensearch.test.framework.testplugins;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.core.rest.RestStatus;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class DummyRestHandler extends BaseRestHandler {

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new NamedRoute.Builder().method(POST)
                .path("/dummy")
                .uniqueName("security:dummy/post")
                .legacyActionNames(Set.of("cluster:admin/dummy_plugin/dummy/post"))
                .build(),
            new NamedRoute.Builder().method(GET)
                .path("/dummy")
                .uniqueName("security:dummy/get")
                .legacyActionNames(Set.of("cluster:admin/dummy_plugin/dummy/get"))
                .build()
        ),
        "/_plugins/_dummyplugin"
    );

    private final Logger log = LogManager.getLogger(this.getClass());

    public DummyRestHandler() {
        super();
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {

            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response = null;

                try {

                    // TODO: do something
                } catch (final Exception e1) {
                    log.error(e1.toString(), e1);
                    builder = channel.newBuilder();
                    builder.startObject();
                    builder.field("error", e1.toString());
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                } finally {
                    if (builder != null) {
                        builder.close();
                    }
                }

                channel.sendResponse(response);
            }
        };
    }

    @Override
    public String getName() {
        return "Dummy Rest Action";
    }

}
