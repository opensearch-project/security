/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;

/**
 * Provides the evaluated REST API permissions for the currently logged in user
 */
public class PermissionsInfoAction extends BaseRestHandler {
	private static final List<Route> routes = Collections.singletonList(
			new Route(Method.GET, "/_opendistro/_security/api/permissionsinfo")
	);

	private final RestApiPrivilegesEvaluator restApiPrivilegesEvaluator;
	private final ThreadPool threadPool;
	private final PrivilegesEvaluator privilegesEvaluator;
	private final ConfigurationRepository configurationRepository;

	protected PermissionsInfoAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
			final AdminDNs adminDNs, final ConfigurationRepository configurationRepository, final ClusterService cs,
			final PrincipalExtractor principalExtractor, final PrivilegesEvaluator privilegesEvaluator, ThreadPool threadPool, AuditLog auditLog) {
		super();
		this.threadPool = threadPool;
		this.privilegesEvaluator = privilegesEvaluator;
		this.restApiPrivilegesEvaluator = new RestApiPrivilegesEvaluator(settings, adminDNs, privilegesEvaluator, principalExtractor, configPath, threadPool);
		this.configurationRepository = configurationRepository;
	}

	@Override
	public String getName() {
		return getClass().getSimpleName();
	}

	@Override
	public List<Route> routes() {
		return routes;
	}

	@Override
	protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
		switch (request.method()) {
		case GET:
			return handleGet(request, client);
		default:
			throw new IllegalArgumentException(request.method() + " not supported");
		}
	}

	private RestChannelConsumer handleGet(RestRequest request, NodeClient client) throws IOException {

        return new RestChannelConsumer() {

            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder(); //NOSONAR
                BytesRestResponse response = null;

                try {

            		final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            		final TransportAddress remoteAddress = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
            		Set<String> userRoles = privilegesEvaluator.mapRoles(user, remoteAddress);
            		Boolean hasApiAccess = restApiPrivilegesEvaluator.currentUserHasRestApiAccess(userRoles);
            		Map<Endpoint, List<Method>> disabledEndpoints = restApiPrivilegesEvaluator.getDisabledEndpointsForCurrentUser(user.getName(), userRoles);
            		if (!configurationRepository.isAuditHotReloadingEnabled()) {
            		   disabledEndpoints.put(Endpoint.AUDIT, ImmutableList.copyOf(Method.values()));
            		}

                    builder.startObject();
                    builder.field("user", user==null?null:user.toString());
                    builder.field("user_name", user==null?null:user.getName()); //NOSONAR
                    builder.field("has_api_access", hasApiAccess);
                    builder.startObject("disabled_endpoints");
                    for(Entry<Endpoint, List<Method>>  entry : disabledEndpoints.entrySet()) {
                    	builder.field(entry.getKey().name(), entry.getValue());
                    }
                    builder.endObject();
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e1) {
                    e1.printStackTrace();
                    builder = channel.newBuilder(); //NOSONAR
                    builder.startObject();
                    builder.field("error", e1.toString());
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                } finally {
                    if(builder != null) {
                        builder.close();
                    }
                }

                channel.sendResponse(response);
            }
        };

	}

}
