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

package org.opensearch.security.dlic.rest.api;

import java.util.List;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.Responses.internalSeverError;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class FlushCacheApiAction extends AbstractApiAction {

    private final static Logger LOGGER = LogManager.getLogger(FlushCacheApiAction.class);

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new Route(Method.DELETE, "/cache"),
            new Route(Method.GET, "/cache"),
            new Route(Method.PUT, "/cache"),
            new Route(Method.POST, "/cache"),
            new Route(Method.DELETE, "/cache/user/{username}")
        )
    );

    @Inject
    public FlushCacheApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super(Endpoint.CACHE, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(this::flushCacheApiRequestHandlers);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    private void flushCacheApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.allMethodsNotImplemented()
            .override(
                Method.DELETE,
                (channel, request, client) -> {
                    if (request.path().contains("/user/")) {
                        // Extract the username from the request
                        final String username = request.param("username");
                        // Validate and handle user-specific cache invalidation
                        handleUserCacheInvalidation(channel, username);
                    }
                    else
                    {
                        client.execute(
                            ConfigUpdateAction.INSTANCE,
                            new ConfigUpdateRequest(CType.lcStringValues().toArray(new String[0])),
                            new ActionListener<>() {

                                @Override
                                public void onResponse(ConfigUpdateResponse configUpdateResponse) {
                                    if (configUpdateResponse.hasFailures()) {
                                        LOGGER.error("Cannot flush cache due to", configUpdateResponse.failures().get(0));
                                        internalSeverError(
                                            channel,
                                            "Cannot flush cache due to " + configUpdateResponse.failures().get(0).getMessage() + "."
                                        );
                                        return;
                                    }
                                    LOGGER.debug("cache flushed successfully");
                                    ok(channel, "Cache flushed successfully.");
                                }

                                @Override
                                public void onFailure(final Exception e) {
                                    LOGGER.error("Cannot flush cache due to", e);
                                    internalSeverError(channel, "Cannot flush cache due to " + e.getMessage() + ".");
                                }

                            }
                        );
                    }
                }
            );
    }

    private void handleUserCacheInvalidation(RestChannel channel, String username) {
        if (username == null || username.isEmpty()) {
            internalSeverError(channel, "No username provided for cache invalidation.");
            return;
        }
        // Use BackendRegistry's method to invalidate cache for the specific user
        securityApiDependencies.backendRegistry().invalidateUserCache(username);
        ok(channel, "Cache invalidated for user: " + username);
    }

    @Override
    protected CType getConfigType() {
        return null;
    }

    @Override
    protected void consumeParameters(final RestRequest request) {
        // not needed
    }
}
