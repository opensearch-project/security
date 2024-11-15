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
import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.PUT;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class ApiTokenApiAction extends AbstractApiAction {

    public static final String NAME_JSON_PROPERTY = "name";

    private static final List<Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(new Route(GET, "/apitokens"), new Route(PUT, "/apitokens/{name}")
        // new Route(DELETE, "/apitokens/{name}"),
        )
    );

    protected ApiTokenApiAction(ClusterService clusterService, ThreadPool threadPool, SecurityApiDependencies securityApiDependencies) {
        super(Endpoint.APITOKENS, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(this::apiTokenApiRequestHandlers);
    }

    @Override
    public String getName() {
        return "API Token actions to retrieve / update configs.";
    }

    @Override
    public List<Route> routes() {
        return ROUTES;
    }

    @Override
    protected CType<ConfigV7> getConfigType() {
        return CType.CONFIG;
    }

    private void apiTokenApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {

        requestHandlersBuilder.override(
            GET,
            (channel, request, client) -> loadConfiguration(getConfigType(), false, false).valid(configuration -> {
                if (!apiTokenIndexExists()) {
                    ok(channel, "empty list");
                } else {
                    ok(channel, "non-empty list");
                }
            }).error((status, toXContent) -> response(channel, status, toXContent))
        ).override(PUT, (channel, request, client) -> loadConfiguration(getConfigType(), false, false).valid(configuration -> {
            String token = createApiToken(request.param(NAME_JSON_PROPERTY), client);
            ok(channel, token + " created successfully");
        }).error((status, toXContent) -> response(channel, status, toXContent)));

    }

    public String createApiToken(String name, Client client) {
        createApiTokenIndexIfAbsent(client);

        return "test-token";
    }

    public Boolean apiTokenIndexExists() {
        return clusterService.state().metadata().hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX);
    }

    public void createApiTokenIndexIfAbsent(Client client) {
        if (!apiTokenIndexExists()) {
            try (final ThreadContext.StoredContext ctx = client.threadPool().getThreadContext().stashContext()) {
                final Map<String, Object> indexSettings = ImmutableMap.of(
                    "index.number_of_shards",
                    1,
                    "index.auto_expand_replicas",
                    "0-all"
                );
                final CreateIndexRequest createIndexRequest = new CreateIndexRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX).settings(
                    indexSettings
                );
                logger.info(client.admin().indices().create(createIndexRequest).actionGet().isAcknowledged());
            }
        }
    }
}
