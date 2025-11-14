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
import java.util.List;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.configuration.SecurityConfigVersionsLoader;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.Responses.payload;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * REST endpoint:
 *   GET /_plugins/_security/api/versions
 */
public class ViewVersionApiAction extends AbstractApiAction {

    private static final Logger LOGGER = LogManager.getLogger(ViewVersionApiAction.class);

    private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(new Route(Method.GET, "/versions")));

    private final SecurityConfigVersionsLoader versionsLoader;

    public ViewVersionApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies,
        final SecurityConfigVersionsLoader versionsLoader
    ) {
        super(Endpoint.VIEW_VERSION, clusterService, threadPool, securityApiDependencies);
        this.versionsLoader = versionsLoader;

        this.requestHandlersBuilder.allMethodsNotImplemented().override(Method.GET, (channel, request, client) -> {
            handleGetRequest(channel, client);
        });
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType<?> getConfigType() {
        return null;
    }

    private void handleGetRequest(org.opensearch.rest.RestChannel channel, org.opensearch.transport.client.Client client)
        throws IOException {
        final ThreadContext threadContext = threadPool.getThreadContext();

        try (ThreadContext.StoredContext ctx = threadContext.stashContext()) {
            var searchRequest = new SearchRequest(ConfigConstants.OPENSEARCH_SECURITY_DEFAULT_CONFIG_VERSIONS_INDEX);
            client.searchAsync(searchRequest)
                .thenAccept(response -> { Responses.ok(channel, response::toXContent); })
                .exceptionally((e) -> {
                    Responses.response(
                        channel,
                        RestStatus.INTERNAL_SERVER_ERROR,
                        payload(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage())
                    );
                    return null;
                });
        } catch (Exception e) {
            Responses.response(channel, RestStatus.INTERNAL_SERVER_ERROR, payload(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage()));
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
            public ValidationResult<SecurityConfiguration> onConfigLoad(SecurityConfiguration securityConfiguration) {
                return ValidationResult.success(securityConfiguration);
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigDelete(SecurityConfiguration securityConfiguration) {
                return ValidationResult.error(RestStatus.FORBIDDEN, Responses.forbiddenMessage("Delete not supported for version view"));
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigChange(SecurityConfiguration securityConfiguration) {
                return ValidationResult.error(RestStatus.FORBIDDEN, Responses.forbiddenMessage("Change not supported for version view"));
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return RequestContentValidator.NOOP_VALIDATOR;
            }
        };
    }
}
