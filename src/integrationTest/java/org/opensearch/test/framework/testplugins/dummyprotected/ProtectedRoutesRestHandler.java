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

package org.opensearch.test.framework.testplugins.dummyprotected;

import java.util.List;
import java.util.Set;

import com.google.common.collect.ImmutableList;

import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestStatusToXContentListener;
import org.opensearch.test.framework.testplugins.AbstractRestHandler;
import org.opensearch.test.framework.testplugins.dummyprotected.dummyaction.DummyAction;
import org.opensearch.test.framework.testplugins.dummyprotected.dummyaction.DummyRequest;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class ProtectedRoutesRestHandler extends AbstractRestHandler {

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new NamedRoute.Builder().method(POST)
                .path("/dummy")
                .uniqueName("security:dummy_protected/post")
                .legacyActionNames(Set.of("cluster:admin/dummy_protected_plugin/dummy/post"))
                .build(),
            new NamedRoute.Builder().method(GET)
                .path("/dummy")
                .uniqueName("security:dummy_protected/get")
                .legacyActionNames(Set.of("cluster:admin/dummy_protected_plugin/dummy/get"))
                .build()
        ),
        "/_plugins/_dummy_protected"
    );

    public ProtectedRoutesRestHandler() {
        super();
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    public String getName() {
        return "Dummy Protected Rest Action";
    }

    @Override
    public void handleGet(RestChannel channel, RestRequest request, NodeClient client) {
        String message = request.param("message");
        DummyRequest dummyRequest = new DummyRequest(message);
        client.execute(DummyAction.INSTANCE, dummyRequest, new RestStatusToXContentListener<>(channel));
    }
}
