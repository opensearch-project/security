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

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.threadpool.ThreadPool;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class AuthTokenProcessorAction extends AbstractApiAction {
    private static final List<Route> routes = addRoutesPrefix(Collections.singletonList(new Route(Method.POST, "/authtoken")));

    @Inject
    public AuthTokenProcessorAction(
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
        this.requestHandlersBuilder.configureRequestHandlers(
            builder -> builder.allMethodsNotImplemented().override(Method.POST, (channel, request, client) -> ok(channel, ""))
        );
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType getConfigType() {
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
