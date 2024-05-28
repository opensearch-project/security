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

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestActions;
import org.opensearch.security.dlic.rest.api.ssl.CertificateType;
import org.opensearch.security.dlic.rest.api.ssl.CertificatesActionType;
import org.opensearch.security.dlic.rest.api.ssl.CertificatesInfoNodesRequest;
import org.opensearch.security.dlic.rest.api.ssl.CertificatesNodesResponse;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.Responses.internalServerError;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.CERTS_INFO_ACTION;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_API_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class CertificatesApiAction extends AbstractApiAction {

    private final static Logger LOGGER = LogManager.getLogger(CertificatesApiAction.class);

    private static final List<Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(new Route(RestRequest.Method.GET, "/certificates"), new Route(RestRequest.Method.GET, "/certificates/{nodeId}")),
        PLUGIN_API_ROUTE_PREFIX
    );

    public CertificatesApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super(Endpoint.SSL, clusterService, threadPool, securityApiDependencies);
        this.requestHandlersBuilder.configureRequestHandlers(this::securitySSLCertsRequestHandlers);
    }

    @Override
    public List<Route> routes() {
        return ROUTES;
    }

    @Override
    public String getName() {
        return "HTTP and Transport Certificates Actions";
    }

    @Override
    protected CType getConfigType() {
        return null;
    }

    @Override
    protected void consumeParameters(RestRequest request) {
        request.param("nodeId");
        request.param("cert_type");
    }

    private void securitySSLCertsRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.withAccessHandler(this::accessHandler)
            .allMethodsNotImplemented()
            .verifyAccessForAllMethods()
            .override(
                RestRequest.Method.GET,
                (channel, request, client) -> client.execute(
                    CertificatesActionType.INSTANCE,
                    new CertificatesInfoNodesRequest(
                        CertificateType.from(request.param("cert_type")),
                        true,
                        request.paramAsStringArrayOrEmptyIfAll("nodeId")
                    ).timeout(request.param("timeout")),
                    new ActionListener<>() {
                        @Override
                        public void onResponse(final CertificatesNodesResponse response) {
                            ok(channel, (builder, params) -> {
                                builder.startObject();
                                RestActions.buildNodesHeader(builder, channel.request(), response);
                                builder.field("cluster_name", response.getClusterName().value());
                                response.toXContent(builder, channel.request());
                                builder.endObject();
                                return builder;
                            });
                        }

                        @Override
                        public void onFailure(Exception e) {
                            LOGGER.error("Cannot load SSL certificates info due to", e);
                            internalServerError(channel, "Cannot load SSL certificates info " + e.getMessage() + ".");
                        }
                    }
                )
            );
    }

    boolean accessHandler(final RestRequest request) {
        if (request.method() == RestRequest.Method.GET) {
            return securityApiDependencies.restApiAdminPrivilegesEvaluator().isCurrentUserAdminFor(endpoint, CERTS_INFO_ACTION);
        } else {
            return false;
        }
    }

}
