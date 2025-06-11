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
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.resources.ResourceSharingIndexHandler.getSharingIndex;
import static org.opensearch.security.spi.resources.FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SampleResourcePluginMigrationApiTests {

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
            client.delete(getSharingIndex(RESOURCE_INDEX_NAME));
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
    public void testMigrateAPIWithRestAdmin_validPayload() {
        createSampleResource();
        createSampleResourceNoUser();

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse migrateResponse = client.postJson(RESOURCE_SHARING_MIGRATION_ENDPOINT, migrationPayload_valid());
            migrateResponse.assertStatusCode(HttpStatus.SC_OK);
            assertThat(migrateResponse.bodyAsMap().get("message"), equalTo("Migration complete. migrated 1; skippedNoUser 1; failed 0"));
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
            assertThat(migrateResponse.bodyAsJsonNode().get("missing_mandatory_keys").get("keys").asText(), equalTo("user.name"));
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
            assertThat(migrateResponse.bodyAsJsonNode().get("missing_mandatory_keys").get("keys").asText(), equalTo("user.backend_roles"));
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

    private void createSampleResource() {
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
}
