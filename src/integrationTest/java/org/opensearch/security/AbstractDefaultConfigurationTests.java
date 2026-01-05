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

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.http.HttpStatus;
import org.awaitility.Awaitility;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

public abstract class AbstractDefaultConfigurationTests {
    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin");
    private static final TestSecurityConfig.User NEW_USER = new TestSecurityConfig.User("new-user");
    private static final TestSecurityConfig.User LIMITED_USER = new TestSecurityConfig.User("limited-user");

    private final LocalCluster cluster;

    protected AbstractDefaultConfigurationTests(LocalCluster cluster) {
        this.cluster = cluster;
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

    private void prepareRolesTestCase() {
        try (var client = cluster.getRestClient(ADMIN_USER)) {
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
            final var alteredRoleReponse = client.patch("_plugins/_security/api/roles/" + roleToAlter, """
                [
                  {
                    "op": "replace",
                    "path": "/cluster_permissions",
                    "value": ["a", "b", "c"]
                  },
                  {
                    "op": "add",
                    "path": "/index_permissions",
                    "value": [ {
                        "index_patterns": ["*"],
                        "allowed_actions": ["*"]
                      }
                    ]
                  }
                ]""");
            alteredRoleReponse.assertStatusCode(200);
            final var alteredRoleJson = alteredRoleReponse.getBodyAs(JsonNode.class);
            assertThat(originalRoleConfig, not(equalTo(alteredRoleJson)));
        }
    }

    @Test
    public void securityUpgrade() throws Exception {
        try (var client = cluster.getRestClient(ADMIN_USER)) {
            // Setup: Make sure the config is ready before starting modifications
            Awaitility.await().alias("Load default configuration").until(() -> client.getAuthInfo().getStatusCode(), equalTo(200));
            // Setup: Collect default roles after cluster start
            final var expectedRoles = client.get("_plugins/_security/api/roles/");
            final var expectedRoleNames = extractFieldNames(expectedRoles.getBodyAs(JsonNode.class));
            final var originalRoleConfig = client.get("_plugins/_security/api/roles/flow_framework_read_access").getBodyAs(JsonNode.class);
            prepareRolesTestCase();
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
            final var afterUpgradeAlteredRoleConfig = client.get("_plugins/_security/api/roles/flow_framework_read_access")
                .getBodyAs(JsonNode.class);
            assertThat(originalRoleConfig, equalTo(afterUpgradeAlteredRoleConfig));
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
            final var originalRoleConfig = client.get("_plugins/_security/api/roles/flow_framework_read_access").getBodyAs(JsonNode.class);
            prepareRolesTestCase();

            // Verify: Confirm that the upgrade check detects the changes associated with both role resources
            final var upgradeCheckAfterChanges = client.get("_plugins/_security/api/_upgrade_check?configs=roles");
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
            final var performUpgrade = client.post("_plugins/_security/api/_upgrade_perform?configs=roles");
            performUpgrade.assertStatusCode(200);
            assertThat(performUpgrade.getTextArrayFromJsonBody("/upgrades/roles/add"), equalTo(List.of("flow_framework_full_access")));
            assertThat(performUpgrade.getTextArrayFromJsonBody("/upgrades/roles/modify"), equalTo(List.of("flow_framework_read_access")));

            // Verify: Same roles as the original state - the deleted role has been restored
            final var afterUpgradeRoles = client.get("_plugins/_security/api/roles/");
            final var afterUpgradeRolesNames = extractFieldNames(afterUpgradeRoles.getBodyAs(JsonNode.class));
            assertThat(afterUpgradeRolesNames, equalTo(expectedRoleNames));

            // Verify: Altered role was restored to its expected state
            final var afterUpgradeAlteredRoleConfig = client.get("_plugins/_security/api/roles/flow_framework_read_access")
                .getBodyAs(JsonNode.class);
            assertThat(originalRoleConfig, equalTo(afterUpgradeAlteredRoleConfig));
        }
    }

    @Test
    public void securityRolesUpgradeSpecifyingRoles() throws Exception {
        try (var client = cluster.getRestClient(ADMIN_USER)) {
            // Setup: Make sure the config is ready before starting modifications
            Awaitility.await().alias("Load default configuration").until(() -> client.getAuthInfo().getStatusCode(), equalTo(200));

            // Setup: Collect default roles after cluster start
            final var expectedRoles = client.get("_plugins/_security/api/roles/");
            final var expectedRoleNames = extractFieldNames(expectedRoles.getBodyAs(JsonNode.class));
            // This test restores flow_framework_read_access, but leaves flow_framework_full_access removed
            final var originalRoleConfig = client.get("_plugins/_security/api/roles/flow_framework_read_access").getBodyAs(JsonNode.class);
            prepareRolesTestCase();

            // Verify: Confirm that the upgrade check detects the changes associated with both role resources
            final var upgradeCheckAfterChanges = client.get(
                "_plugins/_security/api/_upgrade_check?configs=roles&entities=flow_framework_read_access"
            );
            upgradeCheckAfterChanges.assertStatusCode(200);
            assertThat(upgradeCheckAfterChanges.getTextArrayFromJsonBody("/upgradeActions/roles/add"), is(empty()));
            assertThat(
                upgradeCheckAfterChanges.getTextArrayFromJsonBody("/upgradeActions/roles/modify"),
                equalTo(List.of("flow_framework_read_access"))
            );

            // Action: Perform the upgrade to the roles configuration
            final var performUpgrade = client.post(
                "_plugins/_security/api/_upgrade_perform?configs=roles&entities=flow_framework_read_access,flow_framework_full_access"
            );
            performUpgrade.assertStatusCode(200);
            assertThat(performUpgrade.getTextArrayFromJsonBody("/upgrades/roles/add"), is(List.of("flow_framework_full_access")));
            assertThat(performUpgrade.getTextArrayFromJsonBody("/upgrades/roles/modify"), equalTo(List.of("flow_framework_read_access")));

            // Verify: Same roles as the original state - the deleted role has been restored
            final var afterUpgradeRoles = client.get("_plugins/_security/api/roles/");
            final var afterUpgradeRolesNames = extractFieldNames(afterUpgradeRoles.getBodyAs(JsonNode.class));
            assertThat(afterUpgradeRolesNames, equalTo(expectedRoleNames));

            // Verify: Altered role was restored to its expected state
            final var afterUpgradeAlteredRoleConfig = client.get("_plugins/_security/api/roles/flow_framework_read_access")
                .getBodyAs(JsonNode.class);
            assertThat(originalRoleConfig, equalTo(afterUpgradeAlteredRoleConfig));
        }
    }

    private Set<String> extractFieldNames(final JsonNode json) {
        final var set = new HashSet<String>();
        json.fieldNames().forEachRemaining(set::add);
        return set;
    }

}
