/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.rest;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.testplugins.dummy.CustomLegacyTestPlugin;
import org.opensearch.test.framework.testplugins.dummy.LegacyRestHandler;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestHandler.Route.Property.ADMINISTRATIVE;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.junit.Assert.assertEquals;

public class AdministrativeRoutesTest {
    private static final String BASE = "_plugins/_administrative_test";
    private static final String ACTION = "cluster:admin/dummy_plugin/dummy";
    private static final User ACTION_ONLY = new User("action_only").roles(new Role("action_only").clusterPermissions(ACTION));
    private static final User REST_ADMIN = new User("rest_admin").roles(new Role("rest_admin").clusterPermissions(ACTION));
    private static final User ROLE_ONLY = new User("role_only").roles(new Role("role_only"));
    private static final User BACKEND_ROLE_ONLY = new User("backend_role_only").roles(new Role("action").clusterPermissions(ACTION))
        .backendRoles(REST_ADMIN.getRoleNames().iterator().next());

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ACTION_ONLY, REST_ADMIN, ROLE_ONLY, BACKEND_ROLE_ONLY)
        .nodeSettings(
            Map.of(
                "plugins.security.restapi.roles_enabled",
                Stream.concat(REST_ADMIN.getRoleNames().stream(), ROLE_ONLY.getRoleNames().stream()).toList()
            )
        )
        .plugin(AdministrativePlugin.class)
        .build();

    @Test
    public void actionPermissionDoesNotGrantAdministrativeAccess() {
        try (TestRestClient client = cluster.getRestClient(ACTION_ONLY)) {
            TestRestClient.HttpResponse response = client.get(BASE + "/ordinary");
            assertEquals(response.getBody(), 200, response.getStatusCode());
            assertEquals(403, client.get(BASE + "/admin/one").getStatusCode());
            assertEquals(403, client.get(BASE + "/named").getStatusCode());
        }
    }

    @Test
    public void backendRoleNameAloneDoesNotGrantAccess() {
        try (TestRestClient client = cluster.getRestClient(BACKEND_ROLE_ONLY)) {
            assertEquals(403, client.get(BASE + "/admin/one").getStatusCode());
        }
    }

    @Test
    public void restAdminCanAccessAdministrativeRoutes() {
        try (TestRestClient client = cluster.getRestClient(REST_ADMIN)) {
            assertEquals(200, client.get(BASE + "/admin/one").getStatusCode());
            assertEquals(200, client.get(BASE + "/named").getStatusCode());
        }
    }

    @Test
    public void restAdminStillNeedsActionPermissions() {
        try (TestRestClient client = cluster.getRestClient(ROLE_ONLY)) {
            assertEquals(403, client.get(BASE + "/admin/one").getStatusCode());
            assertEquals(403, client.get(BASE + "/named").getStatusCode());
        }
    }

    @Test
    public void adminCertificateRetainsAccess() {
        try (TestRestClient client = cluster.getAdminCertRestClient()) {
            assertEquals(200, client.get(BASE + "/admin/one").getStatusCode());
            assertEquals(200, client.get(BASE + "/named").getStatusCode());
        }
    }

    public static class AdministrativePlugin extends CustomLegacyTestPlugin {
        @Override
        public List<RestHandler> getRestHandlers(
            Settings settings,
            RestController controller,
            ClusterSettings clusterSettings,
            IndexScopedSettings indexSettings,
            SettingsFilter settingsFilter,
            IndexNameExpressionResolver resolver,
            Supplier<DiscoveryNodes> nodes
        ) {
            return List.of(new LegacyRestHandler() {
                @Override
                protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
                    request.param("id");
                    return super.prepareRequest(request, client);
                }

                @Override
                public List<Route> routes() {
                    return List.of(
                        new Route(GET, "/" + BASE + "/ordinary"),
                        new Route(GET, "/" + BASE + "/admin/{id}", ADMINISTRATIVE),
                        new NamedRoute.Builder().method(GET)
                            .path("/" + BASE + "/named")
                            .uniqueName("cluster:admin/administrative_test/get")
                            .legacyActionNames(Set.of(ACTION))
                            .properties(ADMINISTRATIVE)
                            .build()
                    );
                }
            });
        }
    }
}
