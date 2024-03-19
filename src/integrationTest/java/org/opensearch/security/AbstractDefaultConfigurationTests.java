/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.io.FileUtils;
import org.apache.http.HttpStatus;
import org.awaitility.Awaitility;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.security.state.SecurityMetadata;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public abstract class AbstractDefaultConfigurationTests {
    public final static Path configurationFolder = ConfigurationFiles.createConfigurationDirectory();
    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin");
    private static final TestSecurityConfig.User NEW_USER = new TestSecurityConfig.User("new-user");
    private static final TestSecurityConfig.User LIMITED_USER = new TestSecurityConfig.User("limited-user");

    private final LocalCluster cluster;

    protected AbstractDefaultConfigurationTests(LocalCluster cluster) {
        this.cluster = cluster;
    }

    @AfterClass
    public static void cleanConfigurationDirectory() throws IOException {
        FileUtils.deleteDirectory(configurationFolder.toFile());
    }

    @Test
    public void shouldLoadDefaultConfiguration() {
        try (TestRestClient client = cluster.getRestClient(NEW_USER)) {
            Awaitility.await().alias("Load default configuration").until(() -> client.getAuthInfo().getStatusCode(), equalTo(200));
        }
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.confirmCorrectCredentials(ADMIN_USER.getName());
            TestRestClient.HttpResponse response = client.get("_plugins/_security/api/internalusers");
            response.assertStatusCode(HttpStatus.SC_OK);
            Map<String, Object> users = response.getBodyAs(Map.class);
            assertThat(
                response.getBody(),
                users,
                allOf(aMapWithSize(3), hasKey(ADMIN_USER.getName()), hasKey(NEW_USER.getName()), hasKey(LIMITED_USER.getName()))
            );
        }
    }

    void assertClusterState(final TestRestClient client) {
        if (cluster.node().settings().getAsBoolean("plugins.security.allow_default_init_securityindex.use_cluster_state", false)) {
            final TestRestClient.HttpResponse response = client.get("_cluster/state");
            response.assertStatusCode(HttpStatus.SC_OK);
            final var clusterState = response.getBodyAs(Map.class);
            assertTrue(response.getBody(), clusterState.containsKey(SecurityMetadata.TYPE));
            @SuppressWarnings("unchecked")
            final var securityClusterState = (Map<String, Object>) clusterState.get(SecurityMetadata.TYPE);
            @SuppressWarnings("unchecked")
            final var securityConfiguration = (Map<String, Object>) ((Map<?, ?>) clusterState.get(SecurityMetadata.TYPE)).get(
                "configuration"
            );
            assertTrue(response.getBody(), securityClusterState.containsKey("created"));
            assertNotNull(response.getBody(), securityClusterState.get("created"));

            for (final var k : securityConfiguration.keySet()) {
                @SuppressWarnings("unchecked")
                final var sc = (Map<String, Object>) securityConfiguration.get(k);
                assertTrue(response.getBody(), sc.containsKey("hash"));
                assertTrue(response.getBody(), sc.containsKey("last_modified"));
            }
        }
    }

    @Test
    public void securityRolesUpgrade() throws Exception {
        try (var client = cluster.getRestClient(ADMIN_USER)) {
            // Setup: Make sure the config is ready before starting modifications
            Awaitility.await().alias("Load default configuration").until(() -> client.getAuthInfo().getStatusCode(), equalTo(200));

            // Setup: Collect default roles after cluster start
            final var expectedRoles = client.get("_plugins/_security/api/roles/");
            final var expectedRoleNames = extractFieldNames(expectedRoles.getBodyAs(JsonNode.class));

            // Verify: Before any changes, nothing to upgrade
            final var upgradeCheck = client.get("_plugins/_security/api/_upgrade_check");
            upgradeCheck.assertStatusCode(200);
            assertThat(upgradeCheck.getBooleanFromJsonBody("/upgradeAvailable"), equalTo(false));

            // Action: Select a role that is part of the defaults and delete that role
            final var roleToDelete = "flow_framework_full_access";
            client.delete("_plugins/_security/api/roles/" + roleToDelete).assertStatusCode(200);

            // Action: Select a role that is part of the defaults and alter that role with removal, edits, and additions
            final var roleToAlter = "flow_framework_read_access";
            final var originalRoleConfig = client.get("_plugins/_security/api/roles/" + roleToAlter).getBodyAs(JsonNode.class);
            final var alteredRoleReponse = client.patch("_plugins/_security/api/roles/" + roleToAlter, "[\n" + //
                "  {\n" + //
                "    \"op\": \"replace\",\n" + //
                "    \"path\": \"/cluster_permissions\",\n" + //
                "    \"value\": [\"a\", \"b\", \"c\"]\n" + //
                "  },\n" + //
                "  {\n" + //
                "    \"op\": \"add\",\n" + //
                "    \"path\": \"/index_permissions\",\n" + //
                "    \"value\": [ {\n" + //
                "        \"index_patterns\": [\"*\"],\n" + //
                "        \"allowed_actions\": [\"*\"]\n" + //
                "      }\n" + //
                "    ]\n" + //
                "  }\n" + //
                "]");
            alteredRoleReponse.assertStatusCode(200);
            final var alteredRoleJson = alteredRoleReponse.getBodyAs(JsonNode.class);
            assertThat(originalRoleConfig, not(equalTo(alteredRoleJson)));

            // Verify: Confirm that the upgrade check detects the changes associated with both role resources
            final var upgradeCheckAfterChanges = client.get("_plugins/_security/api/_upgrade_check");
            upgradeCheckAfterChanges.assertStatusCode(200);
            assertThat(
                upgradeCheckAfterChanges.getTextArrayFromJsonBody("/upgradeActions/roles/add"),
                equalTo(List.of("flow_framework_full_access"))
            );
            assertThat(
                upgradeCheckAfterChanges.getTextArrayFromJsonBody("/upgradeActions/roles/modify"),
                equalTo(List.of("flow_framework_read_access"))
            );

            // Action: Perform the upgrade to the roles configuration
            final var performUpgrade = client.post("_plugins/_security/api/_upgrade_perform");
            performUpgrade.assertStatusCode(200);
            assertThat(performUpgrade.getTextArrayFromJsonBody("/upgrades/roles/add"), equalTo(List.of("flow_framework_full_access")));
            assertThat(performUpgrade.getTextArrayFromJsonBody("/upgrades/roles/modify"), equalTo(List.of("flow_framework_read_access")));

            // Verify: Same roles as the original state - the deleted role has been restored
            final var afterUpgradeRoles = client.get("_plugins/_security/api/roles/");
            final var afterUpgradeRolesNames = extractFieldNames(afterUpgradeRoles.getBodyAs(JsonNode.class));
            assertThat(afterUpgradeRolesNames, equalTo(expectedRoleNames));

            // Verify: Altered role was restored to its expected state
            final var afterUpgradeAlteredRoleConfig = client.get("_plugins/_security/api/roles/" + roleToAlter).getBodyAs(JsonNode.class);
            assertThat(originalRoleConfig, equalTo(afterUpgradeAlteredRoleConfig));
        }
    }

    private Set<String> extractFieldNames(final JsonNode json) {
        final var set = new HashSet<String>();
        json.fieldNames().forEachRemaining(set::add);
        return set;
    }

}
