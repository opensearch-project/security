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

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;

import com.google.common.collect.ImmutableMap;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.methodNotImplementedMessage;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class SecurityConfigAction extends PatchableResourceApiAction {

    private static final List<Route> getRoutes = addRoutesPrefix(Collections.singletonList(new Route(Method.GET, "/securityconfig/")));

    private static final List<Route> allRoutes = new ImmutableList.Builder<Route>().addAll(getRoutes)
        .addAll(
            addRoutesPrefix(ImmutableList.of(new Route(Method.PUT, "/securityconfig/{name}"), new Route(Method.PATCH, "/securityconfig/")))
        )
        .build();

    private final boolean allowPutOrPatch;

    @Inject
    public SecurityConfigAction(
        final Settings settings,
        final Path configPath,
        final RestController controller,
        final Client client,
        final AdminDNs adminDNs,
        final ConfigurationRepository cl,
        final ClusterService cs,
        final PrincipalExtractor principalExtractor,
        final PrivilegesEvaluator evaluator,
        ThreadPool threadPool,
        AuditLog auditLog
    ) {

        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
        allowPutOrPatch = settings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, false);
    }

    @Override
    public List<Route> routes() {
        return allowPutOrPatch ? allRoutes : getRoutes;
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

    @Override
    protected boolean hasPermissionsToCreate(
        final SecurityDynamicConfiguration<?> dynamicConfigFactory,
        final Object content,
        final String resourceName
    ) {
        return true;
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
    protected void configureRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.onChangeRequest(Method.PUT, request -> {
            if (!allowPutOrPatch) {
                return ValidationResult.error(RestStatus.NOT_IMPLEMENTED, methodNotImplementedMessage(request.method()));
            } else {
                return withConfigResourceNameOnly(request).map(ignore -> processPutRequest(request));
            }
        })
            .override(Method.POST, methodNotImplementedHandler)
            .override(Method.DELETE, methodNotImplementedHandler)
            .override(Method.POST, methodNotImplementedHandler);
    }

    private ValidationResult<String> withConfigResourceNameOnly(final RestRequest request) {
        final var name = nameParam(request);
        if (!"config".equals(name)) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("name must be config"));
        }
        return ValidationResult.success(name);
    }

    @Override
    protected RequestContentValidator createValidator(final Object... params) {
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
                return ImmutableMap.of("dynamic", DataType.OBJECT);
            }
        });
    }

}
