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
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.RolesMappingValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;

public class RolesMappingApiAction extends PatchableResourceApiAction {

	@Inject
	public RolesMappingApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
			final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
            final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);

		controller.registerHandler(Method.GET, "/_opendistro/_security/api/rolesmapping/", this);
		controller.registerHandler(Method.GET, "/_opendistro/_security/api/rolesmapping/{name}", this);
		controller.registerHandler(Method.DELETE, "/_opendistro/_security/api/rolesmapping/{name}", this);
		controller.registerHandler(Method.PUT, "/_opendistro/_security/api/rolesmapping/{name}", this);
        controller.registerHandler(Method.PATCH, "/_opendistro/_security/api/rolesmapping/", this);
        controller.registerHandler(Method.PATCH, "/_opendistro/_security/api/rolesmapping/{name}", this);

	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.ROLESMAPPING;
	}

	@Override
	protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
		return new RolesMappingValidator(request, ref, this.settings, param);
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
