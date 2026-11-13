/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.api;

import java.util.ArrayList;
import java.util.TreeSet;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public class PermissionsApiIntegrationTest extends AbstractApiIntegrationTest {
    @Override
    protected String apiPathPrefix() {
        return PLUGINS_PREFIX;
    }

    private static final TestSecurityConfig.User ROLE_EDITOR = new TestSecurityConfig.User("role-editor").roles(
        new TestSecurityConfig.Role("role-editor").clusterPermissions("restapi:admin/roles")
    );
    private static final TestSecurityConfig.User GROUP_EDITOR = new TestSecurityConfig.User("group-editor").roles(
        new TestSecurityConfig.Role("group-editor").clusterPermissions("restapi:admin/actiongroups")
    );

    @ClassRule
    public static LocalCluster cluster = clusterBuilder().nodeSetting(SECURITY_RESTAPI_ADMIN_ENABLED, true)
        .users(ROLE_EDITOR, GROUP_EDITOR)
        .build();

    @Test
    public void discoversCoreAndPluginActionsForCertificateAdmin() throws Exception {
        try (TestRestClient client = cluster.getAdminCertRestClient()) {
            assertCatalog(client);
        }
    }

    @Test
    public void availableToRoleEditor() throws Exception {
        try (TestRestClient client = cluster.getRestClient(ROLE_EDITOR)) {
            assertCatalog(client);
        }
    }

    @Test
    public void availableThroughRolesEnabled() throws Exception {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            assertCatalog(client);
        }
    }

    @Test
    public void rejectsUnprivilegedUser() throws Exception {
        try (TestRestClient client = cluster.getRestClient(NEW_USER)) {
            assertThat(client.get(apiPath("permissions")), isForbidden());
        }
    }

    @Test
    public void unrelatedRestApiPermissionDoesNotGrantAccess() throws Exception {
        try (TestRestClient client = cluster.getRestClient(GROUP_EDITOR)) {
            assertThat(client.get(apiPath("permissions")), isForbidden());
        }
    }

    private void assertCatalog(TestRestClient client) throws Exception {
        final var response = client.get(apiPath("permissions"));
        assertThat(response, isOk());
        final var body = response.bodyAsJsonNode();
        assertThat(body.get("scope").asString(), is("node"));
        assertThat(body.get("node_id").asString(), not(emptyString()));
        final var names = new ArrayList<String>();
        body.get("registered_actions").forEach(name -> names.add(name.asString()));
        assertThat(names, hasItems("cluster:monitor/health", "indices:data/read/search", "cluster:admin/opendistro_security/whoami"));
        assertThat(names, contains(new TreeSet<>(names).toArray(String[]::new)));
    }
}
