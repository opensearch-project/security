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

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.threadpool.ThreadPool;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.opensearch.rest.RestRequest.Method.*;
import static org.opensearch.security.dlic.rest.api.RateLimitersApiAction.NAME_JSON_PROPERTY;
import static org.opensearch.security.dlic.rest.api.Responses.*;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static org.opensearch.security.securityconf.impl.v7.ConfigV7.*;

public class ApiTokenApiAction extends AbstractApiAction {

    public static final String NAME_JSON_PROPERTY = "ip";


    private static final List<Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(
            new Route(GET, "/apitokens"),
            new Route(PUT, "/apitokens/{name}")
//            new Route(DELETE, "/apitokens/{name}"),
        )
    );

    protected ApiTokenApiAction(ClusterService clusterService, ThreadPool threadPool, SecurityApiDependencies securityApiDependencies) {
        super(Endpoint.APITOKENS, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(this::authFailureConfigApiRequestHandlers);
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

    private void authFailureConfigApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {

        requestHandlersBuilder.override(
            GET,
            (channel, request, client) -> loadConfiguration(getConfigType(), false, false).valid(configuration -> {
                if (!apiTokenIndexExists()) {
                    ok(channel, "empty list");
                } else {
                    ok(channel, "non-empty list");
                }
            }).error((status, toXContent) -> response(channel, status, toXContent)))
        .override(PUT, (channel, request, client) -> loadConfiguration(getConfigType(), false, false).valid(configuration -> {
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
            final Map<String, Object> indexSettings = ImmutableMap.of("index.number_of_shards", 1, "index.auto_expand_replicas", "0-all");
            final CreateIndexRequest createIndexRequest = new CreateIndexRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX).settings(indexSettings);
            logger.info(client.admin().indices().create(createIndexRequest).actionGet().isAcknowledged());
        }
    }
}
