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
            Awaitility.await().alias("Load default configuration").until(() -> client.getAuthInfo().getStatusCode(), equalTo(200));

            final var expectedRoles = client.get("_plugins/_security/api/roles/");
            final var expectedRoleNames = extractFieldNames(expectedRoles.getBodyAs(JsonNode.class));

            final var upgradeCheck = client.get("_plugins/_security/api/_upgrade_check");
            upgradeCheck.assertStatusCode(200);
            assertThat(upgradeCheck.getBooleanFromJsonBody("/upgradeAvailable"), equalTo(false));

            final var roleToDelete = "flow_framework_full_access";
            client.delete("_plugins/_security/api/roles/" + roleToDelete).assertStatusCode(200);

            final var roleToAlter = "flow_framework_read_access";
            client.patch("_plugins/_security/api/roles/" + roleToAlter, "[\n" + //
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
                "]").assertStatusCode(200);

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

            final var performUpgrade = client.post("_plugins/_security/api/_upgrade_perform");
            performUpgrade.assertStatusCode(200);
            assertThat(performUpgrade.getTextArrayFromJsonBody("/upgrades/roles/add"), equalTo(List.of("flow_framework_full_access")));
            assertThat(performUpgrade.getTextArrayFromJsonBody("/upgrades/roles/modify"), equalTo(List.of("flow_framework_read_access")));

            final var afterUpgradeRoles = client.get("_plugins/_security/api/roles/");
            final var afterUpgradeRolesNames = extractFieldNames(afterUpgradeRoles.getBodyAs(JsonNode.class));
            assertThat(afterUpgradeRolesNames, equalTo(expectedRoleNames));
        }
    }

    private Set<String> extractFieldNames(final JsonNode json) {
        final var set = new HashSet<String>();
        json.fieldNames().forEachRemaining(set::add);
        return set;
    }
}
