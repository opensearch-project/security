/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
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
import org.opensearch.security.spi.resources.ResourceAccessLevels;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SAMPLE_RESOURCE_CREATE_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SAMPLE_RESOURCE_DELETE_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SAMPLE_RESOURCE_REVOKE_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SAMPLE_RESOURCE_SHARE_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SAMPLE_RESOURCE_UPDATE_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SHARED_WITH_USER;
import static org.opensearch.sample.SampleResourcePluginTestHelper.revokeAccessPayload;
import static org.opensearch.sample.SampleResourcePluginTestHelper.shareWithPayload;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.resources.ResourceSharingIndexHandler.getSharingIndex;
import static org.opensearch.security.spi.resources.FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with resource sharing enabled and system index protection enabled
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SampleResourcePluginTests {

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
        .anonymousAuth(true)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN, SHARED_WITH_USER)
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
    public void testPluginInstalledCorrectly() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse pluginsResponse = client.get("_cat/plugins");
            assertThat(pluginsResponse.getBody(), containsString("org.opensearch.security.OpenSearchSecurityPlugin"));
            assertThat(pluginsResponse.getBody(), containsString("org.opensearch.sample.SampleResourcePlugin"));
        }
    }

    @Test
    public void testCreateUpdateDeleteSampleResource() throws Exception {
        String resourceId;
        // create sample resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            String sampleResource = """
                {"name":"sample"}
                """;

            TestRestClient.HttpResponse response = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sampleResource);
            response.assertStatusCode(HttpStatus.SC_OK);

            resourceId = response.getTextFromJsonBody("/message").split(":")[1].trim();

            Awaitility.await()
                .alias("Wait until resource data is populated")
                .until(() -> client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId).getStatusCode(), equalTo(200));
        }

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            Awaitility.await()
                .alias("Wait until resource-sharing data is populated")
                .until(() -> client.get(RESOURCE_SHARING_INDEX + "/_search").bodyAsJsonNode().get("hits").get("hits").size(), equalTo(1));
        }

        // Update sample resource (admin should be able to update resource)
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            String sampleResourceUpdated = """
                {"name":"sampleUpdated"}
                """;

            TestRestClient.HttpResponse updateResponse = client.postJson(
                SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId,
                sampleResourceUpdated
            );
            updateResponse.assertStatusCode(HttpStatus.SC_OK);

            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString("sampleUpdated"));
        }

        // resource should not be visible to SHARED_WITH_USER
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {

            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(0));
        }

        // SHARED_WITH_USER should not be able to share admin's resource with itself
        // Only admins and owners can share/revoke access at the moment
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.postJson(
                SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + resourceId,
                shareWithPayload(SHARED_WITH_USER.getName())
            );
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            assertThat(
                response.bodyAsJsonNode().get("error").get("root_cause").get(0).get("reason").asText(),
                containsString("User " + SHARED_WITH_USER.getName() + " is not authorized")
            );
        }

        // share resource with shared_with user
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.postJson(
                SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + resourceId,
                shareWithPayload(SHARED_WITH_USER.getName())
            );
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(
                response.bodyAsJsonNode().get("share_with").get(ResourceAccessLevels.PLACE_HOLDER).get("users").get(0).asText(),
                containsString(SHARED_WITH_USER.getName())
            );
        }

        // resource should now be visible to SHARED_WITH_USER
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString("sampleUpdated"));

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(1));
        }

        // revoke share_with_user's access
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.postJson(
                SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + resourceId,
                revokeAccessPayload(SHARED_WITH_USER.getName())
            );
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), not(containsString("resource_sharing_test_user")));
        }

        // get sample resource with SHARED_WITH_USER, user no longer has access to resource
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(0));
        }

        // delete sample resource with SHARED_WITH_USER
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }

        // delete sample resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // get sample resource with SHARED_WITH_USER
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            Awaitility.await()
                .alias("Wait until resource-sharing data is deleted")
                .until(() -> client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId).getStatusCode(), equalTo(HttpStatus.SC_NOT_FOUND));
        }

        // get sample resource with admin
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Awaitility.await()
                .alias("Wait until resource-sharing data is deleted")
                .until(() -> client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId).getStatusCode(), equalTo(HttpStatus.SC_NOT_FOUND));
        }
    }

    @Test
    public void testDirectAccess() throws Exception {
        String resourceId;
        // create sample resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            String sampleResource = """
                {"name":"sample"}
                """;

            HttpResponse response = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sampleResource);
            response.assertStatusCode(HttpStatus.SC_OK);

            resourceId = response.getTextFromJsonBody("/message").split(":")[1].trim();
        }

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            Awaitility.await()
                .alias("Wait until resource-sharing data is populated")
                .until(() -> client.get(RESOURCE_SHARING_INDEX + "/_search").bodyAsJsonNode().get("hits").get("hits").size(), equalTo(1));
        }

        // admin should not be able to access resource directly since system index protection is enabled, but can access via sample plugin
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.get(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_NOT_FOUND);

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // shared_with_user should not be able to delete the resource since system index protection is enabled
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse response = client.delete(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }

        // shared_with_user should not be able to access resource directly since system index protection is enabled, and resource is not
        // shared with user
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse response = client.get(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_NOT_FOUND);

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }

        // Update sample resource (shared_with_user cannot update admin's resource) because system index protection is enabled
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            String sampleResourceUpdated = """
                {"name":"sampleUpdated"}
                """;

            TestRestClient.HttpResponse updateResponse = client.postJson(
                RESOURCE_INDEX_NAME + "/_doc/" + resourceId,
                sampleResourceUpdated
            );
            updateResponse.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            Awaitility.await()
                .alias("Wait until resource-sharing data is populated")
                .until(() -> client.get(RESOURCE_SHARING_INDEX + "/_search").bodyAsJsonNode().get("hits").get("hits").size(), equalTo(1));
        }

        // share resource with shared_with user
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.postJson(
                SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + resourceId,
                shareWithPayload(SHARED_WITH_USER.getName())
            );
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(
                response.bodyAsJsonNode().get("share_with").get(ResourceAccessLevels.PLACE_HOLDER).get("users").get(0).asText(),
                containsString(SHARED_WITH_USER.getName())
            );
        }

        // shared_with_user should not be able to access resource directly since system index protection is enabled, but can access via
        // sample plugin
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse response = client.get(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_NOT_FOUND);

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            Awaitility.await()
                .alias("Wait until resource-sharing data is populated")
                .until(() -> client.get(RESOURCE_SHARING_INDEX + "/_search").bodyAsJsonNode().get("hits").get("hits").size(), equalTo(1));
        }
        // revoke share_with_user's access
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.postJson(
                SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + resourceId,
                revokeAccessPayload(SHARED_WITH_USER.getName())
            );
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), not(containsString("resource_sharing_test_user")));
        }

        // shared_with_user should not be able to access the resource directly nor via sample plugin since access is revoked
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse response = client.get(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_NOT_FOUND);

            response = client.postJson(RESOURCE_INDEX_NAME + "/_search", "{\"query\" :  {\"match_all\" : {}}}");
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("hits").get("hits").size(), equalTo(0));
        }

    }
}
