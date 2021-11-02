/*
 * Copyright OpenSearch Contributors
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

import java.nio.file.Path;
import java.util.List;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.dlic.rest.validation.RolesValidator;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.threadpool.ThreadPool;

import org.opensearch.security.securityconf.impl.CType;

import com.google.common.collect.ImmutableList;

import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class RolesApiAction extends PatchableResourceApiAction {
	private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
			new Route(Method.GET, "/roles/"),
			new Route(Method.GET, "/roles/{name}"),
			new Route(Method.DELETE, "/roles/{name}"),
			new Route(Method.PUT, "/roles/{name}"),
			new Route(Method.PATCH, "/roles/"),
			new Route(Method.PATCH, "/roles/{name}")
	));

	@Inject
	public RolesApiAction(Settings settings, final Path configPath, RestController controller, Client client, AdminDNs adminDNs, ConfigurationRepository cl,
                          ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
	}

	@Override
	public List<Route> routes() {
		return routes;
	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.ROLES;
	}

	@Override
	protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
		return new RolesValidator(request, isSuperAdmin(), ref, this.settings, param);
	}

	@Override
	protected String getResourceName() {
		return "role";
	}

	@Override
    protected CType getConfigName() {
        return CType.ROLES;
	}

}
