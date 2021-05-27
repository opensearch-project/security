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
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;
import java.util.stream.Collectors;

import org.opensearch.security.dlic.rest.validation.SecurityConfigValidator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.google.common.collect.ImmutableList;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import com.fasterxml.jackson.databind.JsonNode;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class SecurityConfigAction extends PatchableResourceApiAction {

    private static final List<Route> getRoutes = addRoutesPrefix(Collections.singletonList(
            new Route(Method.GET, "/securityconfig/")
    ));

    private static final List<Route> allRoutes = new ImmutableList.Builder<Route>()
            .addAll(getRoutes)
            .addAll(addRoutesPrefix(
                ImmutableList.of(
                    new Route(Method.PUT, "/securityconfig/{name}"),
                    new Route(Method.PATCH, "/securityconfig/")
                )
            ))
            .build();

    private final boolean allowPutOrPatch;

    @Inject
    public SecurityConfigAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                                final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
                                final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {

        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
        allowPutOrPatch = settings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, false);
    }

    @Override
    public List<Route> routes() {
        return allowPutOrPatch ? allRoutes : getRoutes;
    }

    @Override
    protected void handleGet(RestChannel channel, RestRequest request, Client client, final JsonNode content) throws IOException{
        final SecurityDynamicConfiguration<?> configuration = load(getConfigName(), true);

        filter(configuration);

        successResponse(channel, configuration);
    }



    @Override
    protected void handleApiRequest(RestChannel channel, RestRequest request, Client client) throws IOException {
        if (request.method() == Method.PATCH && !allowPutOrPatch) {
            notImplemented(channel, Method.PATCH);
        } else {
            super.handleApiRequest(channel, request, client);
        }
    }

    @Override
    protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException{
        if (allowPutOrPatch) {

            if(!"config".equals(request.param("name"))) {
                badRequestResponse(channel, "name must be config");
                return;
            }

            super.handlePut(channel, request, client, content);
        } else {
            notImplemented(channel, Method.PUT);
        }
    }

    @Override
    protected void handlePost(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException{
        notImplemented(channel, Method.POST);
    }

    @Override
    protected void handleDelete(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException{
        notImplemented(channel, Method.DELETE);
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
        return new SecurityConfigValidator(request, ref, this.settings, param);
    }

    @Override
    protected CType getConfigName() {
        return CType.CONFIG;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.CONFIG;
    }

    @Override
    protected String getResourceName() {
        // not needed, no single resource
        return null;
    }

}
