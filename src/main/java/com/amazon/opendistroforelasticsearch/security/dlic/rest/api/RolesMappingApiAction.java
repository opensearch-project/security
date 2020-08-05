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
import java.util.List;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.RolesMappingValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;

public class RolesMappingApiAction extends PatchableResourceApiAction {
	private static final List<Route> routes = ImmutableList.of(
			new Route(Method.GET, "/_opendistro/_security/api/rolesmapping/"),
			new Route(Method.GET, "/_opendistro/_security/api/rolesmapping/{name}"),
			new Route(Method.DELETE, "/_opendistro/_security/api/rolesmapping/{name}"),
			new Route(Method.PUT, "/_opendistro/_security/api/rolesmapping/{name}"),
			new Route(Method.PATCH, "/_opendistro/_security/api/rolesmapping/"),
			new Route(Method.PATCH, "/_opendistro/_security/api/rolesmapping/{name}")
	);

	@Inject
	public RolesMappingApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
			final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
            final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
	}

	@Override
	protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
		final String name = request.param("name");

		if (name == null || name.length() == 0) {
			badRequestResponse(channel, "No " + getResourceName() + " specified.");
			return;
		}

		final SecurityDynamicConfiguration<?> rolesMappingConfiguration = load(getConfigName(), false);
		final boolean rolesMappingExists = rolesMappingConfiguration.exists(name);

		if (!isValidRolesMapping(channel, name)) return;

		rolesMappingConfiguration.putCObject(name, DefaultObjectMapper.readTree(content, rolesMappingConfiguration.getImplementingClass()));

		saveAnUpdateConfigs(client, request, getConfigName(), rolesMappingConfiguration, new OnSucessActionListener<IndexResponse>(channel) {

			@Override
			public void onResponse(IndexResponse response) {
				if (rolesMappingExists) {
					successResponse(channel, "'" + name + "' updated.");
				} else {
					createdResponse(channel, "'" + name + "' created.");
				}

			}
		});
	}

	@Override
	public List<Route> routes() {
		return routes;
	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.ROLESMAPPING;
	}

	@Override
	protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
		return new RolesMappingValidator(request, isSuperAdmin(), ref, this.settings, param);
	}

	@Override
	protected String getResourceName() {
		return "rolesmapping";
	}

	@Override
    protected CType getConfigName() {
        return CType.ROLESMAPPING;
	}

}
