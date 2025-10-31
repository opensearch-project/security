/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.hc.core5.http.Header;
import org.apache.http.HttpStatus;
import org.awaitility.Awaitility;

import org.opensearch.Version;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.resources.sharing.Recipient;
import org.opensearch.security.resources.sharing.Recipients;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.certificate.CertificateData;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.opensearch.sample.utils.Constants.RESOURCE_GROUP_TYPE;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_PREFIX;
import static org.opensearch.security.resources.ResourceSharingIndexHandler.getSharingIndex;
import static org.opensearch.security.support.ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.security.support.ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Provides common constants and utility methods for testing.
 */
public final class TestUtils {

    public static final String RESOURCE_SHARING_INDEX = getSharingIndex(RESOURCE_INDEX_NAME);

    public final static TestSecurityConfig.User FULL_ACCESS_USER = new TestSecurityConfig.User("resource_sharing_test_user_all_access")
        .roles(new TestSecurityConfig.Role("shared_role").indexPermissions("*").on("*").clusterPermissions("*"));

    // No update permission
    public final static TestSecurityConfig.User LIMITED_ACCESS_USER = new TestSecurityConfig.User(
        "resource_sharing_test_user_Limited_Perms"
    ).roles(
        new TestSecurityConfig.Role("shared_role_limited_perms").clusterPermissions(
            "cluster:admin/sample-resource-plugin/get",
            "cluster:admin/sample-resource-plugin/search",
            "cluster:admin/sample-resource-plugin/create",
            "cluster:admin/security/resource/share",
            "cluster:admin/security/resource/share"
        ).indexPermissions("indices:data/read*").on(RESOURCE_INDEX_NAME)
    );

    // No Permission
    public final static TestSecurityConfig.User NO_ACCESS_USER = new TestSecurityConfig.User("resource_sharing_test_user_no_perms");

    public static final String SAMPLE_READ_ONLY = "sample_read_only";
    public static final String SAMPLE_READ_WRITE = "sample_read_write";
    public static final String SAMPLE_FULL_ACCESS = "sample_full_access";

    public static final String SAMPLE_GROUP_READ_ONLY = "sample_group_read_only";
    public static final String SAMPLE_GROUP_READ_WRITE = "sample_group_read_write";
    public static final String SAMPLE_GROUP_FULL_ACCESS = "sample_group_full_access";

    public static final String SAMPLE_RESOURCE_CREATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/create";
    public static final String SAMPLE_RESOURCE_GET_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/get";
    public static final String SAMPLE_RESOURCE_UPDATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/update";
    public static final String SAMPLE_RESOURCE_DELETE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/delete";
    public static final String SAMPLE_RESOURCE_SEARCH_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/search";

    public static final String SAMPLE_RESOURCE_GROUP_CREATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/group/create";
    public static final String SAMPLE_RESOURCE_GROUP_GET_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/group/get";
    public static final String SAMPLE_RESOURCE_GROUP_UPDATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/group/update";
    public static final String SAMPLE_RESOURCE_GROUP_DELETE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/group/delete";
    public static final String SAMPLE_RESOURCE_GROUP_SEARCH_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/group/search";

    public static final String RESOURCE_SHARING_MIGRATION_ENDPOINT = "_plugins/_security/api/resources/migrate";
    public static final String SECURITY_SHARE_ENDPOINT = "_plugins/_security/api/resource/share";
    public static final String SECURITY_TYPES_ENDPOINT = "_plugins/_security/api/resource/types";
    public static final String SECURITY_LIST_ENDPOINT = "_plugins/_security/api/resource/list";

    public static LocalCluster newCluster(boolean featureEnabled, boolean systemIndexEnabled) {
        return newCluster(featureEnabled, systemIndexEnabled, List.of(RESOURCE_TYPE, RESOURCE_GROUP_TYPE));
    }

    public static LocalCluster newCluster(boolean featureEnabled, boolean systemIndexEnabled, List<String> protectedResourceTypes) {
        return new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS_COORDINATOR)
            .plugin(
                new PluginInfo(
                    SampleResourcePlugin.class.getName(),
                    "classpath plugin",
                    "NA",
                    Version.CURRENT,
                    "21",
                    SampleResourcePlugin.class.getName(),
                    null,
                    List.of(OpenSearchSecurityPlugin.class.getName()),
                    false
                )
            )
            .anonymousAuth(true)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USER_ADMIN, FULL_ACCESS_USER, LIMITED_ACCESS_USER, NO_ACCESS_USER)
            .nodeSettings(
                Map.of(
                    OPENSEARCH_RESOURCE_SHARING_ENABLED,
                    featureEnabled,
                    SECURITY_SYSTEM_INDICES_ENABLED_KEY,
                    systemIndexEnabled,
                    OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES,
                    protectedResourceTypes
                )
            )
            .build();
    }

    public static String directSharePayload(String resourceId, String creator, String target, String accessLevel) {
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

    public static String migrationPayload_valid() {
        return """
            {
              "source_index": "%s",
              "username_path": "%s",
              "backend_roles_path": "%s",
              "default_access_level": {
                "sample-resource": "%s"
              }
            }
            """.formatted(RESOURCE_INDEX_NAME, "user/name", "user/backend_roles", "sample_read_only");
    }

    public static String migrationPayload_valid_withSpecifiedAccessLevel(String accessLevel) {
        return """
            {
             "source_index": "%s",
             "username_path": "%s",
             "backend_roles_path": "%s",
             "default_access_level": {
                 "sample-resource": "%s"
              }
            }
             """.formatted(RESOURCE_INDEX_NAME, "user/name", "user/backend_roles", accessLevel);
    }

    public static String migrationPayload_missingSourceIndex() {
        return """
            {
            "username_path": "%s",
            "backend_roles_path": "%s",
            "default_access_level": {
              "sample-resource": "%s"
             }
            }
            """.formatted("user/name", "user/backend_roles", "sample_read_only");
    }

    public static String migrationPayload_missingUserName() {
        return """
            {
            "source_index": "%s",
            "backend_roles_path": "%s",
            "default_access_level": {
              "sample-resource": "%s"
             }
            }
            """.formatted(RESOURCE_INDEX_NAME, "user/backend_roles", "sample_read_only");
    }

    public static String migrationPayload_missingBackendRoles() {
        return """
            {
            "source_index": "%s",
            "username_path": "%s",
            "default_access_level": {
              "sample-resource": "%s"
             }
            }
            """.formatted(RESOURCE_INDEX_NAME, "user/name", "sample_read_only");
    }

    public static String migrationPayload_missingDefaultAccessLevel() {
        return """
            {
            "source_index": "%s",
            "username_path": "%s",
            "backend_roles_path": "%s"
            }
            """.formatted(RESOURCE_INDEX_NAME, "user/name", "user/backend_roles");
    }

    public static String putSharingInfoPayload(
        String resourceId,
        String resourceType,
        String accessLevel,
        Recipient recipient,
        String entity
    ) {
        return """
            {
              "resource_id": "%s",
              "resource_type": "%s",
              "share_with": {
                "%s" : {
                    "%s": ["%s"]
                }
              }
            }
            """.formatted(resourceId, resourceType, accessLevel, recipient.getName(), entity);
    }

    public static class PatchSharingInfoPayloadBuilder {
        private String resourceId;
        private String resourceType;
        private final Map<String, Recipients> share = new HashMap<>();
        private final Map<String, Recipients> revoke = new HashMap<>();

        public PatchSharingInfoPayloadBuilder resourceId(String resourceId) {
            this.resourceId = resourceId;
            return this;
        }

        public PatchSharingInfoPayloadBuilder resourceType(String resourceType) {
            this.resourceType = resourceType;
            return this;
        }

        public void share(Recipients recipients, String accessLevel) {
            Recipients existing = share.getOrDefault(accessLevel, new Recipients(new HashMap<>()));
            existing.share(recipients);
            share.put(accessLevel, existing);
        }

        public void revoke(Recipients recipients, String accessLevel) {
            Recipients existing = revoke.getOrDefault(accessLevel, new Recipients(new HashMap<>()));
            // intentionally share() is called here since we are building a shareWith object, this final object will be used to remove
            // access
            // think of it as currentShareWith.removeAll(revokeShareWith)
            existing.share(recipients);
            revoke.put(accessLevel, existing);
        }

        private String buildJsonString(Map<String, Recipients> input) {

            List<String> output = new ArrayList<>();
            for (Map.Entry<String, Recipients> entry : input.entrySet()) {
                try {
                    XContentBuilder builder = XContentFactory.jsonBuilder();
                    entry.getValue().toXContent(builder, ToXContent.EMPTY_PARAMS);
                    String recipJson = builder.toString();
                    output.add("""
                        "%s" : %s
                        """.formatted(entry.getKey(), recipJson));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

            }

            return String.join(",", output);

        }

        public String build() {
            String allShares = buildJsonString(share);
            String allRevokes = buildJsonString(revoke);
            return """
                {
                  "resource_id": "%s",
                  "resource_type": "%s",
                  "add": {
                    %s
                  },
                  "revoke": {
                    %s
                  }
                }
                """.formatted(resourceId, resourceType, allShares, allRevokes);
        }
    }

    public static class ApiHelper {
        private final LocalCluster cluster;

        public ApiHelper(LocalCluster cluster) {
            this.cluster = cluster;
        }

        // Wipe out all entries in sample index
        public void wipeOutResourceEntries() {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                // 1) Only run if the index exists
                TestRestClient.HttpResponse exists = client.get(RESOURCE_INDEX_NAME);
                int code = exists.getStatusCode();
                if (code == HttpStatus.SC_NOT_FOUND) {
                    return; // nothing to delete
                }
                exists.assertStatusCode(HttpStatus.SC_OK); // fail fast on anything unexpected

                // 2) Delete-by-query but ignore version conflicts
                String endpoint = RESOURCE_INDEX_NAME + "/_delete_by_query?conflicts=proceed&refresh=true&wait_for_completion=true";

                String jsonBody = "{ \"query\": { \"match_all\": {} } }";
                TestRestClient.HttpResponse resp = client.postJson(endpoint, jsonBody);
                resp.assertStatusCode(HttpStatus.SC_OK);
            }
        }

        // Helper to create a sample resource and return its ID
        public String createSampleResourceAs(TestSecurityConfig.User user, Header... headers) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                String sample = "{\"name\":\"sample\"}";
                TestRestClient.HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample, headers);
                resp.assertStatusCode(HttpStatus.SC_OK);
                return resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }
        }

        public String createSampleResourceGroupAs(TestSecurityConfig.User user, Header... headers) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                String sample = "{\"name\":\"samplegroup\"}";
                TestRestClient.HttpResponse resp = client.putJson(SAMPLE_RESOURCE_GROUP_CREATE_ENDPOINT, sample, headers);
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

        public TestRestClient.HttpResponse getResource(String resourceId, TestSecurityConfig.User user) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            }
        }

        public TestRestClient.HttpResponse getResourceGroup(String resourceGroupId, TestSecurityConfig.User user) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.get(SAMPLE_RESOURCE_GROUP_GET_ENDPOINT + "/" + resourceGroupId);
            }
        }

        private void assertGet(String endpoint, TestSecurityConfig.User user, int status, String expectedString) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                TestRestClient.HttpResponse response = client.get(endpoint);
                response.assertStatusCode(status);
                if (status == HttpStatus.SC_OK) assertThat(response.getBody(), containsString(expectedString));
            }
        }

        public TestRestClient.HttpResponse searchResources(TestSecurityConfig.User user) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.get(SAMPLE_RESOURCE_SEARCH_ENDPOINT);
            }
        }

        public void assertDirectGetSearch(TestSecurityConfig.User user, int status, int expectedHits, String expectedResourceName) {
            assertGetSearch(RESOURCE_INDEX_NAME + "/_search", user, status, expectedHits, expectedResourceName);
        }

        @SuppressWarnings("unchecked")
        private void assertGetSearch(
            String endpoint,
            TestSecurityConfig.User user,
            int status,
            int expectedHits,
            String expectedResourceName
        ) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                TestRestClient.HttpResponse response = client.get(endpoint);
                response.assertStatusCode(status);
                if (status == HttpStatus.SC_OK) {
                    Map<String, Object> hits = (Map<String, Object>) response.bodyAsMap().get("hits");
                    assertThat(((List<String>) hits.get("hits")).size(), is(equalTo(expectedHits)));
                    assertThat(response.getBody(), containsString(expectedResourceName));
                }
            }
        }

        public static void assertSearchResponse(TestRestClient.HttpResponse response, int expectedHits, String expectedResourceName) {
            @SuppressWarnings("unchecked")
            Map<String, Object> hits = (Map<String, Object>) response.bodyAsMap().get("hits");
            assertThat(((List<String>) hits.get("hits")).size(), is(equalTo(expectedHits)));
            if (expectedHits > 0) {
                assertThat(response.getBody(), containsString(expectedResourceName));
            }
        }

        public static String searchAllPayload() {
            return """
                {
                     "query": {
                         "match_all": {}
                     }
                }
                """;
        }

        public static String searchByNamePayload(String name) {
            return """
                        {
                            "query": {
                                "term": {
                                    "name.keyword": {
                                        "value": "%s"
                                    }
                                }
                            }
                        }
                """.formatted(name);
        }

        public TestRestClient.HttpResponse searchResources(String searchPayload, TestSecurityConfig.User user) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchPayload);
            }
        }

        public TestRestClient.HttpResponse searchResourceIndex(String searchPayload, TestSecurityConfig.User user) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.postJson(RESOURCE_INDEX_NAME + "/_search", searchPayload);
            }
        }

        public TestRestClient.HttpResponse searchResourceIndex(TestSecurityConfig.User user) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.get(RESOURCE_INDEX_NAME + "/_search");
            }
        }

        public void assertDirectPostSearch(
            String searchPayload,
            TestSecurityConfig.User user,
            int status,
            int expectedHits,
            String expectedResourceName
        ) {
            assertPostSearch(RESOURCE_INDEX_NAME + "/_search", searchPayload, user, status, expectedHits, expectedResourceName);
        }

        @SuppressWarnings("unchecked")
        private void assertPostSearch(
            String endpoint,
            String searchPayload,
            TestSecurityConfig.User user,
            int status,
            int expectedHits,
            String expectedResourceName
        ) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                TestRestClient.HttpResponse response = client.postJson(endpoint, searchPayload);
                response.assertStatusCode(status);
                if (status == HttpStatus.SC_OK) {
                    Map<String, Object> hits = (Map<String, Object>) response.bodyAsMap().get("hits");
                    assertThat(((List<String>) hits.get("hits")).size(), is(equalTo(expectedHits)));
                    assertThat(response.getBody(), containsString(expectedResourceName));
                }
            }
        }

        public TestRestClient.HttpResponse listResources(TestSecurityConfig.User user) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.get(SAMPLE_RESOURCE_GET_ENDPOINT);
            }
        }

        public TestRestClient.HttpResponse updateResource(String resourceId, TestSecurityConfig.User user, String newName) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                String updatePayload = "{" + "\"name\": \"" + newName + "\"}";
                return client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId, updatePayload);
            }
        }

        public TestRestClient.HttpResponse updateResourceGroup(String resourceGroupId, TestSecurityConfig.User user, String newName) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                String updatePayload = "{" + "\"name\": \"" + newName + "\"}";
                return client.postJson(SAMPLE_RESOURCE_GROUP_UPDATE_ENDPOINT + "/" + resourceGroupId, updatePayload);
            }
        }

        public void assertDirectUpdate(String resourceId, TestSecurityConfig.User user, String newName, int status) {
            assertUpdate(RESOURCE_INDEX_NAME + "/_doc/" + resourceId + "?refresh=true", newName, user, status);
        }

        private void assertUpdate(String endpoint, String newName, TestSecurityConfig.User user, int status) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                String updatePayload = "{" + "\"name\": \"" + newName + "\"}";
                TestRestClient.HttpResponse updateResponse = client.postJson(endpoint, updatePayload);
                updateResponse.assertStatusCode(status);
            }
        }

        public void assertDirectUpdateSharingInfo(
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

        public TestRestClient.HttpResponse shareResource(
            String resourceId,
            TestSecurityConfig.User user,
            TestSecurityConfig.User target,
            String accessLevel
        ) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(resourceId, RESOURCE_TYPE, accessLevel, Recipient.USERS, target.getName())
                );
            }
        }

        public TestRestClient.HttpResponse shareResourceGroup(
            String resourceId,
            TestSecurityConfig.User user,
            TestSecurityConfig.User target,
            String accessLevel
        ) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(resourceId, RESOURCE_GROUP_TYPE, accessLevel, Recipient.USERS, target.getName())
                );
            }
        }

        public TestRestClient.HttpResponse shareResourceByRole(
            String resourceId,
            TestSecurityConfig.User user,
            String targetRole,
            String accessLevel
        ) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(resourceId, RESOURCE_TYPE, accessLevel, Recipient.ROLES, targetRole)
                );
            }
        }

        public TestRestClient.HttpResponse shareResourceGroupByRole(
            String resourceId,
            TestSecurityConfig.User user,
            String targetRole,
            String accessLevel
        ) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(resourceId, RESOURCE_GROUP_TYPE, accessLevel, Recipient.ROLES, targetRole)
                );
            }
        }

        public TestRestClient.HttpResponse revokeResource(
            String resourceId,
            TestSecurityConfig.User user,
            TestSecurityConfig.User target,
            String accessLevel
        ) {
            PatchSharingInfoPayloadBuilder patchBuilder = new PatchSharingInfoPayloadBuilder();
            patchBuilder.resourceType(RESOURCE_TYPE);
            patchBuilder.resourceId(resourceId);
            patchBuilder.revoke(new Recipients(Map.of(Recipient.USERS, Set.of(target.getName()))), accessLevel);
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.patch(TestUtils.SECURITY_SHARE_ENDPOINT, patchBuilder.build());
            }
        }

        public TestRestClient.HttpResponse revokeResourceGroup(
            String resourceId,
            TestSecurityConfig.User user,
            TestSecurityConfig.User target,
            String accessLevel
        ) {
            PatchSharingInfoPayloadBuilder patchBuilder = new PatchSharingInfoPayloadBuilder();
            patchBuilder.resourceType(RESOURCE_GROUP_TYPE);
            patchBuilder.resourceId(resourceId);
            patchBuilder.revoke(new Recipients(Map.of(Recipient.USERS, Set.of(target.getName()))), accessLevel);
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.patch(TestUtils.SECURITY_SHARE_ENDPOINT, patchBuilder.build());
            }
        }

        public void assertDirectDelete(String resourceId, TestSecurityConfig.User user, int status) {
            assertDelete(RESOURCE_INDEX_NAME + "/_doc/" + resourceId, user, status);
        }

        public void assertDirectDeleteResourceSharingRecord(String resourceId, TestSecurityConfig.User user, int status) {
            assertDelete(RESOURCE_SHARING_INDEX + "/_doc/" + resourceId, user, status);
        }

        public TestRestClient.HttpResponse deleteResource(String resourceId, TestSecurityConfig.User user) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);
            }
        }

        public TestRestClient.HttpResponse deleteResourceGroup(String resourceGroupId, TestSecurityConfig.User user) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                return client.delete(SAMPLE_RESOURCE_GROUP_DELETE_ENDPOINT + "/" + resourceGroupId);
            }
        }

        private void assertDelete(String endpoint, TestSecurityConfig.User user, int status) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                TestRestClient.HttpResponse response = client.delete(endpoint);
                response.assertStatusCode(status);
            }
        }

        public void awaitSharingEntry(String resourceId) {
            awaitSharingEntry(resourceId, "admin");
        }

        public void awaitSharingEntry(String resourceId, String expectedString) {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                Awaitility.await("Wait for sharing entry for resource " + resourceId)
                    .pollInterval(Duration.ofMillis(500))
                    .untilAsserted(() -> {
                        TestRestClient.HttpResponse response = client.get(RESOURCE_SHARING_INDEX + "/_doc/" + resourceId);
                        response.assertStatusCode(200);
                        String body = response.getBody();
                        assertThat(body, containsString(expectedString));
                        assertThat(body, containsString(resourceId));
                    });
            }
        }
    }
}
