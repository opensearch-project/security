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

import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator.DataType;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.tools.SecurityAdmin;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.RequestHandler.methodNotImplementedHandler;

/**
 * This class implements GET and PUT operations to manage dynamic AllowlistingSettings.
 * <p>
 * These APIs are only accessible to SuperAdmin since the configuration controls what APIs are accessible by normal users.
 * Eg: If allowlisting is enabled, and a specific API like "/_cat/nodes" is not allowlisted, then only the SuperAdmin can use "/_cat/nodes"
 * These APIs allow the SuperAdmin to enable/disable allowlisting, and also change the list of allowlisted APIs.
 * <p>
 * A SuperAdmin is identified by a certificate which represents a distinguished name(DN).
 * SuperAdmin DN's can be set in {@link ConfigConstants#SECURITY_AUTHCZ_ADMIN_DN}
 * SuperAdmin certificate for the default superuser is stored as a kirk.pem file in config folder of OpenSearch
 * <p>
 * Example calling the PUT API as SuperAdmin using curl (if http basic auth is on):
 * curl -v --cacert path_to_config/root-ca.pem --cert path_to_config/kirk.pem --key path_to_config/kirk-key.pem -XPUT https://localhost:9200/_plugins/_security/api/allowlist -H "Content-Type: application/json" -d’
 * {
 *      "enabled" : false,
 *      "requests" : {"/_cat/nodes": ["GET"], "/_plugins/_security/api/allowlist": ["GET"]}
 * }
 *
 * Example using the PATCH API to change the requests as SuperAdmin:
 * curl -v --cacert path_to_config/root-ca.pem --cert path_to_config/kirk.pem --key path_to_config/kirk-key.pem -XPATCH https://localhost:9200/_plugins/_security/api/allowlist -H "Content-Type: application/json" -d’
 * {
 *      "op":"replace",
 *      "path":"/config/requests",
 *      "value": {"/_cat/nodes": ["GET"], "/_plugins/_security/api/allowlist": ["GET"]}
 * }
 *
 * To update enabled, use the "add" operation instead of the "replace" operation, since boolean variables are not recognized as valid paths when they are false.
 * eg:
 * curl -v --cacert path_to_config/root-ca.pem --cert path_to_config/kirk.pem --key path_to_config/kirk-key.pem -XPATCH https://localhost:9200/_plugins/_security/api/allowlist -H "Content-Type: application/json" -d’
 * {
 *      "op":"add",
 *      "path":"/config/enabled",
 *      "value": true
 * }
 *
 * The backing data is stored in {@link ConfigConstants#SECURITY_CONFIG_INDEX_NAME} which is populated during bootstrap.
 * For existing clusters, {@link SecurityAdmin} tool can
 * be used to populate the index.
 * <p>
 */
public class AllowlistApiAction extends AbstractApiAction {

    private static final List<Route> routes = ImmutableList.of(
        new Route(RestRequest.Method.GET, "/_plugins/_security/api/allowlist"),
        new Route(RestRequest.Method.PUT, "/_plugins/_security/api/allowlist"),
        new Route(RestRequest.Method.PATCH, "/_plugins/_security/api/allowlist")
    );

    @Inject
    public AllowlistApiAction(
        final Endpoint endpoint,
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super(endpoint, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(this::allowListApiRequestHandlers);
    }

    private void allowListApiRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.verifyAccessForAllMethods()
            .onChangeRequest(RestRequest.Method.PATCH, this::processPatchRequest)
            .onChangeRequest(
                RestRequest.Method.PUT,
                request -> loadConfigurationWithRequestContent("config", request).map(this::addEntityToConfig)
            )
            .override(RestRequest.Method.DELETE, methodNotImplementedHandler);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType getConfigType() {
        return CType.ALLOWLIST;
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
                    public Map<String, RequestContentValidator.DataType> allowedKeys() {
                        return ImmutableMap.of("enabled", DataType.BOOLEAN, "requests", DataType.OBJECT);
                    }
                });
            }
        };
    }

}
