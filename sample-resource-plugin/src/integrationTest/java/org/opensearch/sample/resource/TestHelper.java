/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource;

import java.time.Duration;

import org.apache.http.HttpStatus;
import org.awaitility.Awaitility;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.certificate.CertificateData;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_PREFIX;
import static org.opensearch.security.resources.ResourceSharingIndexHandler.getSharingIndex;

/**
 * Provides common constants and utility methods for testing.
 */
public final class TestHelper {

    public static final String RESOURCE_SHARING_INDEX = getSharingIndex(RESOURCE_INDEX_NAME);

    public final static TestSecurityConfig.User FULL_ACCESS_USER = new TestSecurityConfig.User("resource_sharing_test_user_all_access")
        .roles(new TestSecurityConfig.Role("shared_role").indexPermissions("*").on("*").clusterPermissions("*"));

    // No update permission
    public final static TestSecurityConfig.User LIMITED_ACCESS_USER = new TestSecurityConfig.User(
        "resource_sharing_test_user_limited_perms"
    ).roles(
        new TestSecurityConfig.Role("shared_role_limited_perms").clusterPermissions(
            "cluster:admin/sample-resource-plugin/get",
            "cluster:admin/sample-resource-plugin/create",
            "cluster:admin/sample-resource-plugin/share",
            "cluster:admin/sample-resource-plugin/revoke"
        ).indexPermissions("indices:data/read*").on(RESOURCE_INDEX_NAME)
    );

    // No Permission
    public final static TestSecurityConfig.User NO_ACCESS_USER = new TestSecurityConfig.User("resource_sharing_test_user_no_perms");

    public static final TestSecurityConfig.ActionGroup sampleReadOnlyAG = new TestSecurityConfig.ActionGroup(
        "sample_plugin_index_read_access",
        TestSecurityConfig.ActionGroup.Type.INDEX,
        "indices:data/read*",
        "cluster:admin/sample-resource-plugin/get"
    );
    public static final TestSecurityConfig.ActionGroup sampleAllAG = new TestSecurityConfig.ActionGroup(
        "sample_plugin_index_all_access",
        TestSecurityConfig.ActionGroup.Type.INDEX,
        "indices:*",
        "cluster:admin/sample-resource-plugin/*"
    );

    public static final String SAMPLE_RESOURCE_CREATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/create";
    public static final String SAMPLE_RESOURCE_GET_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/get";
    public static final String SAMPLE_RESOURCE_UPDATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/update";
    public static final String SAMPLE_RESOURCE_DELETE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/delete";
    public static final String SAMPLE_RESOURCE_SHARE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/share";
    public static final String SAMPLE_RESOURCE_REVOKE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/revoke";

    static final String RESOURCE_SHARING_MIGRATION_ENDPOINT = "_plugins/_security/api/resources/migrate";

    static String shareWithPayload(String user, String accessLevel) {
        return """
            {
              "share_with": {
                "%s" : {
                    "users": ["%s"]
                }
              }
            }
            """.formatted(accessLevel, user);
    }

    static String directSharePayload(String resourceId, String creator, String target, String accessLevel) {
        return """
            {
              "resource_id": "%s",
              "created_by": {
                "user": "%s"
              },
              "share_with": {
                "%s" : {
                    "users": ["%s"]
                }
              }
            }
            """.formatted(resourceId, creator, accessLevel, target);
    }

    public static String revokeAccessPayload(String user, String accessLevel) {
        return """
            {
              "entities_to_revoke": {
                "%s" : {
                    "users": ["%s"]
                }
              }
            }
            """.formatted(accessLevel, user);

    }

    static String migrationPayload_valid() {
        return """
            {
            "source_index": "%s",
            "username_path": "%s",
            "backend_roles_path": "%s"
            }
            """.formatted(RESOURCE_INDEX_NAME, "user/name", "user/backend_roles");
    }

    static String migrationPayload_valid_withSpecifiedAccessLevel() {
        return """
            {
            "source_index": "%s",
            "username_path": "%s",
            "backend_roles_path": "%s",
            "default_access_level": "%s"
            }
            """.formatted(RESOURCE_INDEX_NAME, "user/name", "user/backend_roles", "read_only");
    }

    static String migrationPayload_missingSourceIndex() {
        return """
            {
            "username_path": "%s",
            "backend_roles_path": "%s"
            }
            """.formatted("user/name", "user/backend_roles");
    }

    static String migrationPayload_missingUserName() {
        return """
            {
            "source_index": "%s",
            "backend_roles_path": "%s"
            }
            """.formatted(RESOURCE_INDEX_NAME, "user/backend_roles");
    }

    static String migrationPayload_missingBackendRoles() {
        return """
            {
            "source_index": "%s",
            "username_path": "%s"
            }
            """.formatted(RESOURCE_INDEX_NAME, "user/name");
    }

    public static class ApiHelper {
        private final LocalCluster cluster;

        public ApiHelper(LocalCluster cluster) {
            this.cluster = cluster;
        }

        // Helper to create a sample resource and return its ID
        public String createSampleResourceAs(TestSecurityConfig.User user) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                String sample = "{\"name\":\"sample\"}";
                TestRestClient.HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                return resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }
        }

        public String createRawResourceAs(CertificateData adminCert) {
            try (TestRestClient client = cluster.getRestClient(adminCert)) {
                String sample = "{\"name\":\"sample\"}";
                TestRestClient.HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_CREATED);
                return resp.getTextFromJsonBody("/_id");
            }
        }

        public void assertDirectGet(String resourceId, TestSecurityConfig.User user, int status, String expectedResourceName) {
            assertGet(RESOURCE_INDEX_NAME + "/_doc/" + resourceId, user, status, expectedResourceName);
        }

        public void assertDirectViewSharingRecord(String resourceId, TestSecurityConfig.User user, int status) {
            assertGet(RESOURCE_SHARING_INDEX + "/_doc/" + resourceId, user, status, user.getName());
        }

        public void assertApiGet(String resourceId, TestSecurityConfig.User user, int status, String expectedResourceName) {
            assertGet(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId, user, status, expectedResourceName);
        }

        private void assertGet(String endpoint, TestSecurityConfig.User user, int status, String expectedString) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                TestRestClient.HttpResponse response = client.get(endpoint);
                response.assertStatusCode(status);
                if (status == HttpStatus.SC_OK) assertThat(response.getBody(), containsString(expectedString));
            }
        }

        public void assertDirectGetAll(TestSecurityConfig.User user, int status, String expectedResourceName) {
            assertGetAll(RESOURCE_INDEX_NAME + "/_search", user, status, expectedResourceName);
        }

        public void assertApiGetAll(TestSecurityConfig.User user, int status, String expectedResourceName) {
            assertGetAll(SAMPLE_RESOURCE_GET_ENDPOINT, user, status, expectedResourceName);
        }

        private void assertGetAll(String endpoint, TestSecurityConfig.User user, int status, String expectedResourceName) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                Awaitility.await("Wait until index is refreshed").pollInterval(Duration.ofMillis(500)).untilAsserted(() -> {
                    TestRestClient.HttpResponse response = client.get(endpoint);
                    response.assertStatusCode(status);
                    if (status == HttpStatus.SC_OK) {
                        assertThat(response.bodyAsJsonNode().get("resources").size(), greaterThanOrEqualTo(1));
                        assertThat(response.getBody(), containsString(expectedResourceName));
                    }
                });
            }
        }

        public void assertApiUpdate(String resourceId, TestSecurityConfig.User user, int status) {
            assertUpdate(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId, user, status);
        }

        public void assertDirectUpdate(String resourceId, TestSecurityConfig.User user, int status) {
            assertUpdate(RESOURCE_INDEX_NAME + "/_doc/" + resourceId, user, status);
        }

        private void assertUpdate(String endpoint, TestSecurityConfig.User user, int status) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                String updatePayload = "{" + "\"name\": \"sampleUpdated\"" + "}";
                TestRestClient.HttpResponse updateResponse = client.postJson(endpoint, updatePayload);
                updateResponse.assertStatusCode(status);
            }
        }

        public void assertDirectShare(
            String resourceId,
            TestSecurityConfig.User user,
            TestSecurityConfig.User target,
            String accessLevel,
            int status
        ) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                TestRestClient.HttpResponse response = client.postJson(
                    RESOURCE_SHARING_INDEX + "/_doc/" + resourceId,
                    directSharePayload(resourceId, user.getName(), target.getName(), accessLevel)
                );
                response.assertStatusCode(status);
            }
        }

        public void assertApiShare(
            String resourceId,
            TestSecurityConfig.User user,
            TestSecurityConfig.User target,
            String accessLevel,
            int status
        ) {
            assertShare(SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + resourceId, user, target, accessLevel, status);
        }

        private void assertShare(
            String endpoint,
            TestSecurityConfig.User user,
            TestSecurityConfig.User target,
            String accessLevel,
            int status
        ) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                TestRestClient.HttpResponse response = client.postJson(endpoint, shareWithPayload(target.getName(), accessLevel));
                response.assertStatusCode(status);
            }
        }

        public void assertDirectRevoke(
            String resourceId,
            TestSecurityConfig.User user,
            TestSecurityConfig.User target,
            String accessLevel,
            int status
        ) {
            assertRevoke(RESOURCE_SHARING_INDEX + "/_doc/" + resourceId, user, target, accessLevel, status);
        }

        public void assertApiRevoke(
            String resourceId,
            TestSecurityConfig.User user,
            TestSecurityConfig.User target,
            String accessLevel,
            int status
        ) {
            assertRevoke(SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + resourceId, user, target, accessLevel, status);
        }

        private void assertRevoke(
            String endpoint,
            TestSecurityConfig.User user,
            TestSecurityConfig.User target,
            String accessLevel,
            int status
        ) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                TestRestClient.HttpResponse response = client.postJson(endpoint, revokeAccessPayload(target.getName(), accessLevel));
                response.assertStatusCode(status);
            }
        }

        public void assertDirectDelete(String resourceId, TestSecurityConfig.User user, int status) {
            assertDelete(RESOURCE_INDEX_NAME + "/_doc/" + resourceId, user, status);
        }

        public void assertDirectDeleteResourceSharingRecord(String resourceId, TestSecurityConfig.User user, int status) {
            assertDelete(RESOURCE_SHARING_INDEX + "/_doc/" + resourceId, user, status);
        }

        public void assertApiDelete(String resourceId, TestSecurityConfig.User user, int status) {
            assertDelete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId, user, status);
        }

        private void assertDelete(String endpoint, TestSecurityConfig.User user, int status) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                TestRestClient.HttpResponse response = client.delete(endpoint);
                response.assertStatusCode(status);
            }
        }

        public void awaitSharingEntry() {
            awaitSharingEntry("admin");
        }

        public void awaitSharingEntry(String expectedString) {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                Awaitility.await("Wait for sharing entry").pollInterval(Duration.ofMillis(500)).untilAsserted(() -> {
                    TestRestClient.HttpResponse response = client.get(RESOURCE_SHARING_INDEX + "/_search");
                    response.assertStatusCode(200);
                    String hitsJson = response.bodyAsMap().get("hits").toString();
                    assertThat(hitsJson, containsString(expectedString));
                    int size = response.bodyAsJsonNode().get("hits").get("hits").size();
                    assertThat(size, greaterThanOrEqualTo(1));
                });
            }
        }
    }
}
