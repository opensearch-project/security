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

import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.ActionGroupValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;

public class ActionGroupsApiAction extends PatchableResourceApiAction {

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.ACTIONGROUPS;
	}

	@Inject
	public ActionGroupsApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
								 final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
								 final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);

		// legacy mapping for backwards compatibility
		// TODO: remove in next version
		controller.registerHandler(Method.GET, "/_opendistro/_security/api/actiongroup/{name}", this);
		controller.registerHandler(Method.GET, "/_opendistro/_security/api/actiongroup/", this);
		controller.registerHandler(Method.DELETE, "/_opendistro/_security/api/actiongroup/{name}", this);
		controller.registerHandler(Method.PUT, "/_opendistro/_security/api/actiongroup/{name}", this);

		// corrected mapping, introduced in Open Distro Security
		controller.registerHandler(Method.GET, "/_opendistro/_security/api/actiongroups/{name}", this);
		controller.registerHandler(Method.GET, "/_opendistro/_security/api/actiongroups/", this);
		controller.registerHandler(Method.DELETE, "/_opendistro/_security/api/actiongroups/{name}", this);
		controller.registerHandler(Method.PUT, "/_opendistro/_security/api/actiongroups/{name}", this);
		controller.registerHandler(Method.PATCH, "/_opendistro/_security/api/actiongroups/", this);
		controller.registerHandler(Method.PATCH, "/_opendistro/_security/api/actiongroups/{name}", this);

	}

	@Override
	protected AbstractConfigurationValidator getValidator(final RestRequest request, BytesReference ref, Object... param) {
		return new ActionGroupValidator(request, ref, this.settings, param);
	}

	@Override
	protected CType getConfigName() {
		return CType.ACTIONGROUPS;
	}

	@Override
    protected String getResourceName() {
        return "actiongroup";
	}

	@Override
	protected void consumeParameters(final RestRequest request) {
		request.param("name");
	}

}
