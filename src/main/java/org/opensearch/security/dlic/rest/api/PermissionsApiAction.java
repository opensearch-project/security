/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.dlic.rest.api;

import java.util.List;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * Discovers registered actions for role editing, using the same access policy as the roles API.
 * This is not a list of the caller's effective permissions or a complete permission catalog:
 * transport-only subactions, Security virtual permissions, and action groups are not included.
 */
public class PermissionsApiAction extends AbstractApiAction {
    public PermissionsApiAction(
        ClusterService clusterService,
        ThreadPool threadPool,
        SecurityApiDependencies dependencies,
        RegisteredActions registeredActions
    ) {
        super(Endpoint.ROLES, clusterService, threadPool, dependencies);
        requestHandlersBuilder.allMethodsNotImplemented()
            .override(Method.GET, (channel, request, client) -> ok(channel, (builder, params) -> {
                builder.startObject();
                builder.field("node_id", clusterService.localNode().getId());
                builder.field("scope", "node");
                builder.field("registered_actions", registeredActions.names());
                return builder.endObject();
            }));
    }

    @Override
    public List<Route> routes() {
        return addRoutesPrefix(List.of(new Route(Method.GET, "/permissions")));
    }

    @Override
    protected CType<?> getConfigType() {
        return null;
    }
}
