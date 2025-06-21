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

package org.opensearch.sample;

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
import org.opensearch.painless.PainlessModulePlugin;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.sample.SampleResourcePluginTestHelper.RESOURCE_SHARING_MIGRATION_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SAMPLE_RESOURCE_CREATE_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.migrationPayload_missingBackendRoles;
import static org.opensearch.sample.SampleResourcePluginTestHelper.migrationPayload_missingSourceIndex;
import static org.opensearch.sample.SampleResourcePluginTestHelper.migrationPayload_missingUserName;
import static org.opensearch.sample.SampleResourcePluginTestHelper.migrationPayload_valid;
import static org.opensearch.sample.SampleResourcePluginTestHelper.migrationPayload_valid_withSpecifiedAccessLevel;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.resources.ResourceSharingIndexHandler.getSharingIndex;
import static org.opensearch.security.spi.resources.FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SampleResourcePluginMigrationApiTests {

    private static final String RESOURCE_SHARING_INDEX = getSharingIndex(RESOURCE_INDEX_NAME);

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .plugin(PainlessModulePlugin.class)
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
        .users(USER_ADMIN)
        .nodeSettings(Map.of(SECURITY_SYSTEM_INDICES_ENABLED_KEY, true, OPENSEARCH_RESOURCE_SHARING_ENABLED, true))
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
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse migrateResponse = client.postJson(RESOURCE_SHARING_MIGRATION_ENDPOINT, migrationPayload_valid());
            migrateResponse.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }
    }

    @Test
    public void testMigrateAPIWithRestAdmin_valid() {
        String resourceId = createSampleResource();
        createSampleResourceNoUser();
        clearResourceSharingEntries();

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse migrateResponse = client.postJson(RESOURCE_SHARING_MIGRATION_ENDPOINT, migrationPayload_valid());
            migrateResponse.assertStatusCode(HttpStatus.SC_OK);
            assertThat(migrateResponse.bodyAsMap().get("message"), equalTo("Migration complete. migrated 1; skippedNoUser 1; failed 0"));

            TestRestClient.HttpResponse sharingResponse = client.get(RESOURCE_SHARING_INDEX + "/_search");
            sharingResponse.assertStatusCode(HttpStatus.SC_OK);
            assertThat(sharingResponse.bodyAsJsonNode().get("hits").get("hits").size(), equalTo(1)); // 1 of 2 entries was skipped
            assertThat(sharingResponse.bodyAsJsonNode().get("hits").get("hits"), equalTo(expectedHits(resourceId, "default"))); // with
                                                                                                                                // default
                                                                                                                                // access-level
        }
    }

    @Test
    public void testMigrateAPIWithRestAdmin_valid_withSpecifiedAccessLevel() {
        String resourceId = createSampleResource();
        createSampleResourceNoUser();
        clearResourceSharingEntries();

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse migrateResponse = client.postJson(
                RESOURCE_SHARING_MIGRATION_ENDPOINT,
                migrationPayload_valid_withSpecifiedAccessLevel()
            );
            migrateResponse.assertStatusCode(HttpStatus.SC_OK);
            assertThat(migrateResponse.bodyAsMap().get("message"), equalTo("Migration complete. migrated 1; skippedNoUser 1; failed 0"));

            TestRestClient.HttpResponse sharingResponse = client.get(RESOURCE_SHARING_INDEX + "/_search");
            sharingResponse.assertStatusCode(HttpStatus.SC_OK);
            assertThat(sharingResponse.bodyAsJsonNode().get("hits").get("hits").size(), equalTo(1)); // 1 of 2 entries was skipped
            assertThat(sharingResponse.bodyAsJsonNode().get("hits").get("hits"), equalTo(expectedHits(resourceId, "read_only"))); // with
                                                                                                                                  // custom
                                                                                                                                  // access-level
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
            migrateResponse.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(migrateResponse.bodyAsJsonNode().get("missing_mandatory_keys").get("keys").asText(), equalTo("username_path"));
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
            migrateResponse.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(migrateResponse.bodyAsJsonNode().get("missing_mandatory_keys").get("keys").asText(), equalTo("backend_roles_path"));
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
            migrateResponse.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(migrateResponse.bodyAsJsonNode().get("missing_mandatory_keys").get("keys").asText(), equalTo("source_index"));
        }
    }

    private String createSampleResource() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
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

    private void createSampleResourceNoUser() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
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

    private ArrayNode expectedHits(String resourceId, String accessLevel) {

        ObjectMapper mapper = new ObjectMapper();

        // 1) Create the root array
        ArrayNode expectedHits = mapper.createArrayNode();

        // 2) Create the hit object
        ObjectNode hit = mapper.createObjectNode();
        hit.put("_index", RESOURCE_SHARING_INDEX);
        hit.put("_id", resourceId);
        hit.put("_score", 1.0);

        // 3) Build the _source sub-object
        ObjectNode source = hit.putObject("_source");
        source.put("resource_id", resourceId);

        ObjectNode createdBy = source.putObject("created_by");
        createdBy.put("user", "admin");

        ObjectNode shareWith = source.putObject("share_with");
        ObjectNode readOnly = shareWith.putObject(accessLevel);
        ArrayNode backendRoles = readOnly.putArray("backend_roles");
        backendRoles.add("admin");

        // 4) Add the hit into the array
        expectedHits.add(hit);
        return expectedHits;
    }
}
