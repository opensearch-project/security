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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.NodesDn;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.tools.SecurityAdmin;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.Responses.forbiddenMessage;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * This class implements CRUD operations to manage dynamic NodesDn. The primary usecase is targeted at cross-cluster where
 * in node restart can be avoided by populating the coordinating cluster's nodes_dn values.
 *
 * The APIs are only accessible to SuperAdmin since the configuration controls the core application layer trust validation.
 * By default the APIs are disabled and can be enabled by a YML setting - {@link ConfigConstants#SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED}
 *
 * The backing data is stored in {@link ConfigConstants#SECURITY_CONFIG_INDEX_NAME} which is populated during bootstrap.
 * For existing clusters, {@link SecurityAdmin} tool can
 * be used to populate the index.
 *
 * See {@link NodesDnApiTest} for usage examples.
 */
public class NodesDnApiAction extends AbstractApiAction {

    public static final String STATIC_OPENSEARCH_YML_NODES_DN = "STATIC_OPENSEARCH_YML_NODES_DN";
    private final List<String> staticNodesDnFromEsYml;

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new Route(Method.GET, "/nodesdn/{name}"),
            new Route(Method.GET, "/nodesdn"),
            new Route(Method.DELETE, "/nodesdn/{name}"),
            new Route(Method.PUT, "/nodesdn/{name}"),
            new Route(Method.PATCH, "/nodesdn"),
            new Route(Method.PATCH, "/nodesdn/{name}")
        )
    );

    @Inject
    public NodesDnApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super(Endpoint.NODESDN, clusterService, threadPool, securityApiDependencies);
        this.staticNodesDnFromEsYml = securityApiDependencies.settings().getAsList(ConfigConstants.SECURITY_NODES_DN, List.of());
        this.requestHandlersBuilder.configureRequestHandlers(this::nodesDnApiRequestHandlers);
    }

    @Override
    public List<Route> routes() {
        if (securityApiDependencies.settings().getAsBoolean(ConfigConstants.SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, false)) {
            return routes;
        }
        return Collections.emptyList();
    }

    @Override
    protected CType getConfigType() {
        return CType.NODESDN;
    }

    @Override
    protected void consumeParameters(final RestRequest request) {
        request.param("name");
        request.param("show_all");
    }

    private void nodesDnApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.verifyAccessForAllMethods().onGetRequest(request -> processGetRequest(request).map(securityConfiguration -> {
            if (request.paramAsBoolean("show_all", false)) {
                final var configuration = securityConfiguration.configuration();
                addStaticNodesDn(configuration);
            }
            return ValidationResult.success(securityConfiguration);
        })).onChangeRequest(Method.PATCH, this::processPatchRequest);
    }

    @SuppressWarnings("unchecked")
    private void addStaticNodesDn(SecurityDynamicConfiguration<?> configuration) {
        if (NodesDn.class.equals(configuration.getImplementingClass())) {
            NodesDn nodesDn = new NodesDn();
            nodesDn.setNodesDn(staticNodesDnFromEsYml);
            ((SecurityDynamicConfiguration<NodesDn>) configuration).putCEntry(STATIC_OPENSEARCH_YML_NODES_DN, nodesDn);
        } else {
            throw new RuntimeException("Unknown class type - " + configuration.getImplementingClass());
        }
    }

    @Override
    protected EndpointValidator createEndpointValidator() {
        return new EndpointValidator() {

            @Override
            public Endpoint endpoint() {
                return endpoint;
            }

            @Override
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return securityApiDependencies.restApiAdminPrivilegesEvaluator();
            }

            @Override
            public ValidationResult<SecurityConfiguration> isAllowedToChangeImmutableEntity(SecurityConfiguration securityConfiguration)
                throws IOException {
                if (STATIC_OPENSEARCH_YML_NODES_DN.equals(securityConfiguration.entityName())) {
                    return ValidationResult.error(
                        RestStatus.FORBIDDEN,
                        forbiddenMessage("Resource '" + STATIC_OPENSEARCH_YML_NODES_DN + "' is read-only.")
                    );
                }
                return EndpointValidator.super.isAllowedToChangeImmutableEntity(securityConfiguration);
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
                    @Override
                    public Object[] params() {
                        return params;
                    }

                    @Override
                    public Settings settings() {
                        return securityApiDependencies.settings();
                    }

                    @Override
                    public Set<String> mandatoryKeys() {
                        return ImmutableSet.of("nodes_dn");
                    }

                    @Override
                    public Map<String, DataType> allowedKeys() {
                        return ImmutableMap.of("nodes_dn", DataType.ARRAY);
                    }
                });
            }
        };
    }

}
