/*
 * Copyright 2015-2017 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
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

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;

import com.google.common.collect.ImmutableMap;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class TenantsApiAction extends AbstractApiAction {

    protected final static String RESOURCE_NAME = "tenant";

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new Route(Method.GET, "/tenants/{name}"),
            new Route(Method.GET, "/tenants/"),
            new Route(Method.DELETE, "/tenants/{name}"),
            new Route(Method.PUT, "/tenants/{name}"),
            new Route(Method.PATCH, "/tenants/"),
            new Route(Method.PATCH, "/tenants/{name}")
        )
    );

    @Inject
    public TenantsApiAction(
        final Settings settings,
        final Path configPath,
        final AdminDNs adminDNs,
        final ConfigurationRepository cl,
        final ClusterService cs,
        final PrincipalExtractor principalExtractor,
        final PrivilegesEvaluator evaluator,
        ThreadPool threadPool,
        AuditLog auditLog
    ) {
        super(settings, configPath, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
        this.requestHandlersBuilder.configureRequestHandlers(builder -> builder.onChangeRequest(Method.PATCH, this::processPatchRequest));
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.TENANTS;
    }

    @Override
    protected CType getConfigType() {
        return CType.TENANTS;
    }

    @Override
    protected String getResourceName() {
        return RESOURCE_NAME;
    }

    @Override
    protected EndpointValidator createEndpointValidator() {
        return new EndpointValidator() {
            @Override
            public String resourceName() {
                return RESOURCE_NAME;
            }

            @Override
            public Endpoint endpoint() {
                return getEndpoint();
            }

            @Override
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return restApiAdminPrivilegesEvaluator;
            }

            @Override
            public RequestContentValidator createRequestContentValidator(final Object... params) {
                return RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
                    @Override
                    public Object[] params() {
                        return params;
                    }

                    @Override
                    public Settings settings() {
                        return settings;
                    }

                    @Override
                    public Map<String, RequestContentValidator.DataType> allowedKeys() {
                        final ImmutableMap.Builder<String, DataType> allowedKeys = ImmutableMap.builder();
                        if (isCurrentUserAdmin()) {
                            allowedKeys.put("reserved", DataType.BOOLEAN);
                        }
                        return allowedKeys.put("description", DataType.STRING).build();
                    }
                });
            }
        };
    }

}
