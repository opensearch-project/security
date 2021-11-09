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

import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.dlic.rest.validation.NoOpValidator;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class AuthTokenProcessorAction extends AbstractApiAction {
	private static final List<Route> routes = addRoutesPrefix(Collections.singletonList(
			new Route(Method.POST, "/authtoken")
	));

	@Inject
	public AuthTokenProcessorAction(final Settings settings, final Path configPath, final RestController controller,
                                    final Client client, final AdminDNs adminDNs, final ConfigurationRepository cl,
                                    final ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator,
                                    ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool,
				auditLog);
	}

	@Override
	public List<Route> routes() {
		return routes;
	}

	@Override
	protected void handlePost(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {

		// Just do nothing here. Eligible authenticators will intercept calls and
		// provide own responses.
	    successResponse(channel,"");
	}

	@Override
	protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
		return new NoOpValidator(request, ref, this.settings, param);
	}

	@Override
	protected String getResourceName() {
		return "authtoken";
	}

	@Override
    protected CType getConfigName() {
		return null;
	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.AUTHTOKEN;
	}


	public static class Response {
		private String authorization;

		public String getAuthorization() {
			return authorization;
		}

		public void setAuthorization(String authorization) {
			this.authorization = authorization;
		}
	}
}
