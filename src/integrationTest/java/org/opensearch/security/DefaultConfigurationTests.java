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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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

            final var defaultRolesResponse = client.get("_plugins/_security/api/roles/");
            final var rolesNames = extractFieldNames(defaultRolesResponse.getBodyAs(JsonNode.class));

            final var checkForUpgrade = client.get("_plugins/_security/api/_upgrade_check");
            System.out.println("checkForUpgrade Response: " + checkForUpgrade.getBody());

            final var roleToDelete = "flow_framework_full_access";
            final var deleteRoleResponse = client.delete("_plugins/_security/api/roles/" + roleToDelete);
            deleteRoleResponse.assertStatusCode(200);

            final var checkForUpgrade3 = client.get("_plugins/_security/api/_upgrade_check");
            System.out.println("checkForUpgrade3 Response: " + checkForUpgrade3.getBody());

            final var roleToAlter = "flow_framework_read_access";
            final String patchBody = "[{ \"op\": \"replace\", \"path\": \"/cluster_permissions\", \"value\":"
                + "[\"a\",\"b\",\"c\"]"
                + "},{ \"op\": \"add\", \"path\": \"/index_permissions\", \"value\":"
                + "[{\"index_patterns\":[\"*\"],\"allowed_actions\":[\"*\"]}]"
                + "}]";
            final var updateRoleResponse = client.patch("_plugins/_security/api/roles/" + roleToAlter, patchBody);
            updateRoleResponse.assertStatusCode(200);
            System.out.println("Updated Role Response: " + updateRoleResponse.getBody());

            final var checkForUpgrade2 = client.get("_plugins/_security/api/_upgrade_check");
            System.out.println("checkForUpgrade2 Response: " + checkForUpgrade2.getBody());

            final var upgradeResponse = client.post("_plugins/_security/api/_upgrade_perform");
            System.out.println("upgrade Response: " + upgradeResponse.getBody());

            final var afterUpgradeRolesResponse = client.get("_plugins/_security/api/roles/");
            final var afterUpgradeRolesNames = extractFieldNames(afterUpgradeRolesResponse.getBodyAs(JsonNode.class));
            assertThat(afterUpgradeRolesResponse.getBody(), afterUpgradeRolesNames, equalTo(rolesNames));
        }
    }

    private List<String> extractFieldNames(final JsonNode json) {
        final var list = new ArrayList<String>();
        json.fieldNames().forEachRemaining(list::add);
        return list;
    }
}
