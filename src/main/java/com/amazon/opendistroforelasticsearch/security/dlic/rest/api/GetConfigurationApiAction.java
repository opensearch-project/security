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


import java.nio.file.Path;
import java.util.Set;

import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.IndexBaseConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.NoOpValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.google.common.base.Joiner;

/**
 * @deprecated Use GET endpoints without resource ID in resource specific endpoints, e.g. _opendistro/_security/api/roles/
 * Will be removed in next version.
 */
public class GetConfigurationApiAction extends AbstractApiAction {

	@Inject
	public GetConfigurationApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
			final AdminDNs adminDNs, final IndexBaseConfigurationRepository cl, final ClusterService cs,
            final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
	}

	@Override
	protected void registerHandlers(RestController controller, Settings settings) {
		controller.registerHandler(Method.GET, "/_opendistro/_security/api/configuration/{configname}", this);
		System.out.println("Registering Handler");
	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.CONFIGURATION;
	}

	@Override
	protected void handleGet(RestChannel channel, RestRequest request, Client client,
							 final Settings.Builder additionalSettingsBuilder) {

		final String configname = request.param("configname");

		if (configname == null || configname.length() == 0
				|| !ConfigConstants.CONFIG_NAMES.contains(configname)) {
			badRequestResponse(channel, "No configuration name given, must be one of "
					+ Joiner.on(",").join(ConfigConstants.CONFIG_NAMES));
			return;

		}
		final Tuple<Long, Settings.Builder> configBuilder = load(configname, true);
		filter(configBuilder.v2(), configname);
		final Settings config = configBuilder.v2().build();

		channel.sendResponse(
				new BytesRestResponse(RestStatus.OK, convertToJson(channel, config)));
		return;
	}

	protected void filter(Settings.Builder builder, String resourceName) {
		// common filtering
		filter(builder);
		// filter sensitive resources for internal users
		if (resourceName.equals("internalusers")) {
			filterHashes(builder);
		}
	}

	@Override
	protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
		return new NoOpValidator(request, ref, this.settings, param);
	}

	@Override
	protected String getResourceName() {
		// GET is handled by this class directly
		return null;
	}

	@Override
	protected String getConfigName() {
		// GET is handled by this class directly
		return null;
	}

	@Override
	protected void consumeParameters(final RestRequest request) {
		request.param("configname");
	}

	private void filterHashes(Settings.Builder builder) {
		// replace password hashes in addition. We must not remove them from the
		// Builder since this would remove users completely if they
		// do not have any addition properties like roles or attributes
		Set<String> entries = builder.build().names();
		for (String key : entries) {
			builder.put(key + ".hash", "");
		}
	}
}