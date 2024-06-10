/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

package org.opensearch.security.rest;

import java.io.IOException;
import java.util.List;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.client.node.NodeClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.LEGACY_PLUGIN_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class DashboardsInfoAction extends BaseRestHandler {

    private static final List<Route> routes = ImmutableList.<Route>builder()
        .addAll(
            addRoutesPrefix(ImmutableList.of(new Route(GET, "/dashboardsinfo"), new Route(POST, "/dashboardsinfo")), PLUGIN_ROUTE_PREFIX)
        )
        .addAll(
            addRoutesPrefix(ImmutableList.of(new Route(GET, "/kibanainfo"), new Route(POST, "/kibanainfo")), LEGACY_PLUGIN_ROUTE_PREFIX)
        )
        .build();

    private final Logger log = LogManager.getLogger(this.getClass());
    private final PrivilegesEvaluator evaluator;
    private final ThreadContext threadContext;

    public static final String DEFAULT_PASSWORD_MESSAGE = "Password should be at least 8 characters long and contain at least one "
        + "uppercase letter, one lowercase letter, one digit, and one special character.";

    public static final String DEFAULT_PASSWORD_REGEX = "(?=.*[A-Z])(?=.*[^a-zA-Z\\d])(?=.*[0-9])(?=.*[a-z]).{8,}";

    public DashboardsInfoAction(
        final Settings settings,
        final RestController controller,
        final PrivilegesEvaluator evaluator,
        final ThreadPool threadPool
    ) {
        super();
        this.threadContext = threadPool.getThreadContext();
        this.evaluator = evaluator;
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {

            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder(); // NOSONAR
                BytesRestResponse response = null;

                try {

                    final User user = (User) threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

                    builder.startObject();
                    builder.field("user_name", user == null ? null : user.getName());
                    builder.field("not_fail_on_forbidden_enabled", evaluator.notFailOnForbiddenEnabled());
                    builder.field("opensearch_dashboards_mt_enabled", evaluator.multitenancyEnabled());
                    builder.field("opensearch_dashboards_index", evaluator.dashboardsIndex());
                    builder.field("opensearch_dashboards_server_user", evaluator.dashboardsServerUsername());
                    builder.field("multitenancy_enabled", evaluator.multitenancyEnabled());
                    builder.field("private_tenant_enabled", evaluator.privateTenantEnabled());
                    builder.field("default_tenant", evaluator.dashboardsDefaultTenant());
                    builder.field("sign_in_options", evaluator.getSignInOptions());
                    builder.field(
                        "password_validation_error_message",
                        client.settings().get(ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE, DEFAULT_PASSWORD_MESSAGE)
                    );
                    builder.field(
                        "password_validation_regex",
                        client.settings().get(ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, DEFAULT_PASSWORD_REGEX)
                    );
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e1) {
                    log.error(e1.toString());
                    builder = channel.newBuilder(); // NOSONAR
                    builder.startObject();
                    builder.field("error", e1.toString());
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                } finally {
                    if (builder != null) {
                        builder.close();
                    }
                }

                channel.sendResponse(response);
            }
        };
    }

    @Override
    public String getName() {
        return "Kibana Info Action";
    }

}
