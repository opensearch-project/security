/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.sample.resource.securityapis;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.HttpStatus;
import org.awaitility.Awaitility;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.Version;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.matcher.RestMatchers;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_MIGRATION_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_CREATE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.migrationPayload_missingBackendRoles;
import static org.opensearch.sample.resource.TestUtils.migrationPayload_missingDefaultAccessLevel;
import static org.opensearch.sample.resource.TestUtils.migrationPayload_missingDefaultOwner;
import static org.opensearch.sample.resource.TestUtils.migrationPayload_missingSourceIndex;
import static org.opensearch.sample.resource.TestUtils.migrationPayload_missingUserName;
import static org.opensearch.sample.resource.TestUtils.migrationPayload_valid;
import static org.opensearch.sample.resource.TestUtils.migrationPayload_valid_withSpecifiedAccessLevel;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.security.resources.ResourceSharingIndexHandler.getSharingIndex;
import static org.opensearch.security.support.ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.security.support.ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class MigrateApiTests {

    private static final String RESOURCE_SHARING_INDEX = getSharingIndex(RESOURCE_INDEX_NAME);

    public final static TestSecurityConfig.User MIGRATION_USER = new TestSecurityConfig.User("migration_user").roles(
        new TestSecurityConfig.Role("allaccess").indexPermissions("*").on("*").clusterPermissions("*")
    ).backendRoles("admin");

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.DEFAULT)
        .plugin(
            new PluginInfo(
                SampleResourcePlugin.class.getName(),
                "classpath plugin",
                "NA",
                Version.CURRENT,
                "1.8",
                SampleResourcePlugin.class.getName(),
                null,
                List.of(OpenSearchSecurityPlugin.class.getName()),
                false
            )
        )
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(MIGRATION_USER)
        .nodeSettings(
            Map.of(
                SECURITY_SYSTEM_INDICES_ENABLED_KEY,
                true,
                OPENSEARCH_RESOURCE_SHARING_ENABLED,
                true,
                OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES,
                List.of(RESOURCE_TYPE)
            )
        )
        .build();

    @After
    public void clearIndices() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(RESOURCE_INDEX_NAME);
            client.delete(RESOURCE_SHARING_INDEX);
        }
    }

    @Test
    public void testMigrateAPIWithNormalAdminUser_forbidden() {
        createSampleResource();
        try (TestRestClient client = cluster.getRestClient(MIGRATION_USER)) {
            TestRestClient.HttpResponse migrateResponse = client.postJson(RESOURCE_SHARING_MIGRATION_ENDPOINT, migrationPayload_valid());
            migrateResponse.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }
    }

    @Test
    public void testMigrateAPIWithRestAdmin_valid() {
        String resourceId = createSampleResource();
        String resourceIdNoUser = createSampleResourceNoUser();
        clearResourceSharingEntries();

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse migrateResponse = client.postJson(RESOURCE_SHARING_MIGRATION_ENDPOINT, migrationPayload_valid());
            migrateResponse.assertStatusCode(HttpStatus.SC_OK);
            assertThat(migrateResponse.bodyAsMap().get("summary"), equalTo("Migration complete. migrated 2; skippedNoType 0; failed 0"));
            assertThat(migrateResponse.bodyAsMap().get("resourcesWithDefaultOwner"), equalTo(List.of(resourceIdNoUser)));

            TestRestClient.HttpResponse sharingResponse = client.get(RESOURCE_SHARING_INDEX + "/_search");
            sharingResponse.assertStatusCode(HttpStatus.SC_OK);
            ArrayNode hitsNode = (ArrayNode) sharingResponse.bodyAsJsonNode().get("hits").get("hits");
            assertThat(hitsNode.size(), equalTo(2));

            List<ObjectNode> actualHits = new ArrayList<>();
            hitsNode.forEach(node -> actualHits.add((ObjectNode) node));

            // with custom access level, order-agnostic
            assertThat(
                actualHits,
                containsInAnyOrder(expectedHits(resourceId, resourceIdNoUser, "sample_read_only").toArray(new ObjectNode[0]))
            );

        }
    }

    @Test
    public void testMigrateAPIWithRestAdmin_valid_withSpecifiedAccessLevel() {
        String resourceId = createSampleResource();
        String resourceIdNoUser = createSampleResourceNoUser();
        clearResourceSharingEntries();

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse migrateResponse = client.postJson(
                RESOURCE_SHARING_MIGRATION_ENDPOINT,
                migrationPayload_valid_withSpecifiedAccessLevel("sample_read_write")
            );
            migrateResponse.assertStatusCode(HttpStatus.SC_OK);
            assertThat(migrateResponse.bodyAsMap().get("summary"), equalTo("Migration complete. migrated 2; skippedNoType 0; failed 0"));
            assertThat(migrateResponse.bodyAsMap().get("resourcesWithDefaultOwner"), equalTo(List.of(resourceIdNoUser)));

            TestRestClient.HttpResponse sharingResponse = client.get(RESOURCE_SHARING_INDEX + "/_search");
            sharingResponse.assertStatusCode(HttpStatus.SC_OK);
            ArrayNode hitsNode = (ArrayNode) sharingResponse.bodyAsJsonNode().get("hits").get("hits");
            assertThat(hitsNode.size(), equalTo(2));

            List<ObjectNode> actualHits = new ArrayList<>();
            hitsNode.forEach(node -> actualHits.add((ObjectNode) node));

            // with default access level, order-agnostic
            assertThat(
                actualHits,
                containsInAnyOrder(expectedHits(resourceId, resourceIdNoUser, "sample_read_write").toArray(new ObjectNode[0]))
            );
        }
    }

    @Test
    public void testMigrateAPIWithRestAdmin_noUser() {
        createSampleResource();

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse migrateResponse = client.postJson(
                RESOURCE_SHARING_MIGRATION_ENDPOINT,
                migrationPayload_missingUserName()
            );
            assertThat(migrateResponse, RestMatchers.isBadRequest("/missing_mandatory_keys/keys", "username_path"));
        }
    }

    @Test
    public void testMigrateAPIWithRestAdmin_noBackendRole() {
        createSampleResource();

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse migrateResponse = client.postJson(
                RESOURCE_SHARING_MIGRATION_ENDPOINT,
                migrationPayload_missingBackendRoles()
            );
            assertThat(migrateResponse, RestMatchers.isBadRequest("/missing_mandatory_keys/keys", "backend_roles_path"));
        }
    }

    @Test
    public void testMigrateAPIWithRestAdmin_noSourceIndex() {
        createSampleResource();

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse migrateResponse = client.postJson(
                RESOURCE_SHARING_MIGRATION_ENDPOINT,
                migrationPayload_missingSourceIndex()
            );
            assertThat(migrateResponse, RestMatchers.isBadRequest("/missing_mandatory_keys/keys", "source_index"));
        }
    }

    @Test
    public void testMigrateAPIWithRestAdmin_noDefaultOwner() {
        createSampleResource();

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse migrateResponse = client.postJson(
                RESOURCE_SHARING_MIGRATION_ENDPOINT,
                migrationPayload_missingDefaultOwner()
            );
            assertThat(migrateResponse, RestMatchers.isBadRequest("/missing_mandatory_keys/keys", "default_owner"));
        }
    }

    @Test
    public void testMigrateAPIWithRestAdmin_noDefaultAccessLevel() {
        createSampleResource();

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse migrateResponse = client.postJson(
                RESOURCE_SHARING_MIGRATION_ENDPOINT,
                migrationPayload_missingDefaultAccessLevel()
            );
            assertThat(migrateResponse, RestMatchers.isBadRequest("/missing_mandatory_keys/keys", "default_access_level"));
        }
    }

    @Test
    public void testMigrateAPIWithRestAdmin_invalidDefaultAccessLevel() {
        createSampleResource();

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse migrateResponse = client.postJson(
                RESOURCE_SHARING_MIGRATION_ENDPOINT,
                migrationPayload_valid_withSpecifiedAccessLevel("blah")
            );
            assertThat(
                migrateResponse,
                RestMatchers.isBadRequest(
                    "/message",
                    "Invalid access level blah for resource sharing for resource type [" + RESOURCE_TYPE + "]"
                )
            );
        }
    }

    private String createSampleResource() {
        try (TestRestClient client = cluster.getRestClient(MIGRATION_USER)) {
            String sampleResource = """
                {
                    "name":"sample",
                    "store_user": true
                }
                """;

            TestRestClient.HttpResponse response = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sampleResource);

            String resourceId = response.getTextFromJsonBody("/message").split(":")[1].trim();

            Awaitility.await()
                .alias("Wait until resource data is populated")
                .until(() -> client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId).getStatusCode(), equalTo(200));
            return resourceId;
        }
    }

    private String createSampleResourceNoUser() {
        try (TestRestClient client = cluster.getRestClient(MIGRATION_USER)) {
            String sampleResource = """
                {
                    "name":"sample2"
                }
                """;

            TestRestClient.HttpResponse response = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sampleResource);

            String resourceId = response.getTextFromJsonBody("/message").split(":")[1].trim();

            Awaitility.await()
                .alias("Wait until resource data is populated")
                .until(() -> client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId).getStatusCode(), equalTo(200));
            return resourceId;
        }
    }

    // Since the plugins is labelled as resource-sharing-plugin and we create resource post labelling it as such,
    // corresponding sharing entries are automatically created in the sharing index.
    // To mimic the actual migration behavior, we clear out any existing entries to allow the migrate API to work as expected
    private void clearResourceSharingEntries() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {

            String deleteBody = """
                {
                  "query": {
                    "match_all": {}
                  }
                }
                """;
            TestRestClient.HttpResponse response = client.postJson(RESOURCE_SHARING_INDEX + "/_delete_by_query?refresh=true", deleteBody);

            response.assertStatusCode(HttpStatus.SC_OK);

            client.delete(RESOURCE_SHARING_INDEX + "/?ignore_unavailable=true");
        }
    }

    private List<ObjectNode> expectedHits(String resourceId, String resourceIdNoUser, String accessLevel) {

        ObjectMapper mapper = new ObjectMapper();

        ObjectNode hitWithDefaultUser = mapper.createObjectNode();
        ObjectNode hitWithMigratedUser = mapper.createObjectNode();

        populateNode(hitWithMigratedUser, resourceId, MIGRATION_USER.getName(), accessLevel);
        populateNode(hitWithDefaultUser, resourceIdNoUser, "some_user", accessLevel);

        return List.of(hitWithDefaultUser, hitWithMigratedUser);
    }

    private void populateNode(ObjectNode hit, String resourceId, String username, String accessLevel) {
        // 2) Create the hit object
        hit.put("_index", RESOURCE_SHARING_INDEX);
        hit.put("_id", resourceId);
        hit.put("_score", 1.0);

        // 3) Build the _source sub-object
        ObjectNode source = hit.putObject("_source");
        source.put("resource_id", resourceId);

        ObjectNode createdBy = source.putObject("created_by");
        createdBy.put("user", username);

        if (username.equals(MIGRATION_USER.getName())) {
            ObjectNode shareWith = source.putObject("share_with");
            ObjectNode readOnly = shareWith.putObject(accessLevel);
            ArrayNode backendRoles = readOnly.putArray("backend_roles");
            backendRoles.add("admin");
        }
    }
}
