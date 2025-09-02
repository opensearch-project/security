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
import org.opensearch.security.spi.resources.sharing.Recipients;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.certificate.CertificateData;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_PREFIX;
import static org.opensearch.security.resources.ResourceSharingIndexHandler.getSharingIndex;
import static org.opensearch.security.support.ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
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
        "cluster:admin/sample-resource-plugin/*",
        "cluster:admin/security/resource/share"
    );

    public static final String SAMPLE_RESOURCE_CREATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/create";
    public static final String SAMPLE_RESOURCE_GET_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/get";
    public static final String SAMPLE_RESOURCE_UPDATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/update";
    public static final String SAMPLE_RESOURCE_DELETE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/delete";
    public static final String SAMPLE_RESOURCE_SEARCH_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/search";
    public static final String SAMPLE_RESOURCE_SHARE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/share";
    public static final String SAMPLE_RESOURCE_REVOKE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/revoke";

    static final String RESOURCE_SHARING_MIGRATION_ENDPOINT = "_plugins/_security/api/resources/migrate";
    static final String SECURITY_SHARE_ENDPOINT = "_plugins/_security/api/resource/share";

    public static LocalCluster newCluster(boolean featureEnabled, boolean systemIndexEnabled) {
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
            .actionGroups(sampleReadOnlyAG, sampleAllAG)
            .nodeSettings(
                Map.of(OPENSEARCH_RESOURCE_SHARING_ENABLED, featureEnabled, SECURITY_SYSTEM_INDICES_ENABLED_KEY, systemIndexEnabled)
            )
            .build();
    }

    public static String shareWithPayload(String user, String accessLevel) {
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

    static String putSharingInfoPayload(String resourceId, String resourceIndex, String accessLevel, String user) {
        return """
            {
              "resource_id": "%s",
              "resource_type": "%s",
              "share_with": {
                "%s" : {
                    "users": ["%s"]
                }
              }
            }
            """.formatted(resourceId, resourceIndex, accessLevel, user);
    }

    public static class PatchSharingInfoPayloadBuilder {
        private String resourceId;
        private String resourceIndex;
        private final Map<String, Recipients> share = new HashMap<>();
        private final Map<String, Recipients> revoke = new HashMap<>();

        public PatchSharingInfoPayloadBuilder resourceId(String resourceId) {
            this.resourceId = resourceId;
            return this;
        }

        public PatchSharingInfoPayloadBuilder resourceIndex(String resourceIndex) {
            this.resourceIndex = resourceIndex;
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
                """.formatted(resourceId, resourceIndex, allShares, allRevokes);
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

        public void assertApiGetSearchForbidden(TestSecurityConfig.User user) {
            assertGetSearch(SAMPLE_RESOURCE_SEARCH_ENDPOINT, user, HttpStatus.SC_FORBIDDEN, 0, null);
        }

        public void assertDirectGetSearchForbidden(TestSecurityConfig.User user) {
            assertGetSearch(RESOURCE_INDEX_NAME + "/_search", user, HttpStatus.SC_FORBIDDEN, 0, null);
        }

        public void assertApiGetSearch(TestSecurityConfig.User user, int status, int expectedHits, String expectedResourceName) {
            assertGetSearch(SAMPLE_RESOURCE_SEARCH_ENDPOINT, user, status, expectedHits, expectedResourceName);
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

        public void assertApiPostSearchForbidden(String searchPayload, TestSecurityConfig.User user) {
            assertPostSearch(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchPayload, user, HttpStatus.SC_FORBIDDEN, 0, null);
        }

        public void assertDirectPostSearchForbidden(String searchPayload, TestSecurityConfig.User user) {
            assertPostSearch(RESOURCE_INDEX_NAME + "/_search", searchPayload, user, HttpStatus.SC_FORBIDDEN, 0, null);
        }

        public void assertApiPostSearch(
            String searchPayload,
            TestSecurityConfig.User user,
            int status,
            int expectedHits,
            String expectedResourceName
        ) {
            assertPostSearch(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchPayload, user, status, expectedHits, expectedResourceName);
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
                System.out.println("User: " + user);
                System.out.println("Search response: " + response.getBody());
                response.assertStatusCode(status);
                if (status == HttpStatus.SC_OK) {
                    Map<String, Object> hits = (Map<String, Object>) response.bodyAsMap().get("hits");
                    assertThat(((List<String>) hits.get("hits")).size(), is(equalTo(expectedHits)));
                    assertThat(response.getBody(), containsString(expectedResourceName));
                }
            }

            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                TestRestClient.HttpResponse response = client.postJson(endpoint, searchPayload);
                System.out.println("SuperAdmin: " + user);
                System.out.println("Search response: " + response.getBody());
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

        public void assertApiUpdate(String resourceId, TestSecurityConfig.User user, String newName, int status) {
            assertUpdate(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId, newName, user, status);
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
