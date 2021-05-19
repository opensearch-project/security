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

package org.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import org.opensearch.action.ActionListener;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.dlic.rest.validation.NoOpValidator;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.threadpool.ThreadPool;

import com.fasterxml.jackson.databind.JsonNode;
import org.opensearch.security.securityconf.impl.CType;

import com.google.common.collect.ImmutableList;

public class FlushCacheApiAction extends AbstractApiAction {
	private static final List<Route> routes = ImmutableList.of(
			new Route(Method.DELETE, "/_opendistro/_security/api/cache"),
			new Route(Method.GET, "/_opendistro/_security/api/cache"),
			new Route(Method.PUT, "/_opendistro/_security/api/cache"),
			new Route(Method.POST, "/_opendistro/_security/api/cache")
	);

	@Inject
	public FlushCacheApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                               final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
                               final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
	}

	@Override
	public List<Route> routes() {
		return routes;
	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.CACHE;
	}

	@Override
	protected void handleDelete(RestChannel channel,
	        RestRequest request, Client client, final JsonNode content) throws IOException
	{

		client.execute(
				ConfigUpdateAction.INSTANCE,
				new ConfigUpdateRequest(CType.lcStringValues().toArray(new String[0])),
				new ActionListener<ConfigUpdateResponse>() {

					@Override
					public void onResponse(ConfigUpdateResponse ur) {
					    if(ur.hasFailures()) {
					        log.error("Cannot flush cache due to", ur.failures().get(0));
	                        internalErrorResponse(channel, "Cannot flush cache due to "+ ur.failures().get(0).getMessage()+".");
	                        return;
	                    }
						successResponse(channel, "Cache flushed successfully.");
						if (log.isDebugEnabled()) {
						    log.debug("cache flushed successfully");
						}
					}

					@Override
					public void onFailure(Exception e) {
					    log.error("Cannot flush cache due to", e);
						internalErrorResponse(channel, "Cannot flush cache due to "+ e.getMessage()+".");
					}

				}
		);
	}

	@Override
	protected void handlePost(RestChannel channel, final RestRequest request, final Client client, final JsonNode content)throws IOException {
		notImplemented(channel, Method.POST);
	}

	@Override
	protected void handleGet(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException{
		notImplemented(channel, Method.GET);
	}

	@Override
	protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException{
		notImplemented(channel, Method.PUT);
	}

	@Override
	protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
		return new NoOpValidator(request, ref, this.settings, param);
	}

	@Override
	protected String getResourceName() {
		// not needed
		return null;
	}

	@Override
    protected CType getConfigName() {
		return null;
	}

	@Override
	protected void consumeParameters(final RestRequest request) {
		// not needed
	}
}
