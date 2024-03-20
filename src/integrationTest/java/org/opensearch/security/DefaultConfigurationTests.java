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
import org.awaitility.Awaitility;
import org.junit.AfterClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DefaultConfigurationTests {

    private final static Path configurationFolder = ConfigurationFiles.createConfigurationDirectory();
    private static final User ADMIN_USER = new User("admin");
    private static final User NEW_USER = new User("new-user");
    private static final User LIMITED_USER = new User("limited-user");

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .nodeSettings(
            Map.of(
                "plugins.security.allow_default_init_securityindex",
                true,
                "plugins.security.restapi.roles_enabled",
                List.of("user_admin__all_access")
            )
        )
        .defaultConfigurationInitDirectory(configurationFolder.toString())
        .loadConfigurationIntoIndex(false)
        .build();

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
            HttpResponse response = client.get("_plugins/_security/api/internalusers");
            response.assertStatusCode(200);
            Map<String, Object> users = response.getBodyAs(Map.class);
            assertThat(
                users,
                allOf(aMapWithSize(3), hasKey(ADMIN_USER.getName()), hasKey(NEW_USER.getName()), hasKey(LIMITED_USER.getName()))
            );
        }
    }

    @Test
    public void securityRolesUgrade() throws Exception {
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
