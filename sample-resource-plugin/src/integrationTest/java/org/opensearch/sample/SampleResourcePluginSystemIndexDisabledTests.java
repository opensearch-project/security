/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample;

import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.awaitility.Awaitility;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.painless.PainlessModulePlugin;
import org.opensearch.sample.resource.client.ResourceSharingClientAccessor;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.spi.resources.ResourceAccessActionGroups;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SAMPLE_RESOURCE_CREATE_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SAMPLE_RESOURCE_DELETE_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SAMPLE_RESOURCE_REVOKE_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SAMPLE_RESOURCE_SHARE_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SAMPLE_RESOURCE_UPDATE_ENDPOINT;
import static org.opensearch.sample.SampleResourcePluginTestHelper.SHARED_WITH_USER;
import static org.opensearch.sample.SampleResourcePluginTestHelper.createResourceAccessControlClient;
import static org.opensearch.sample.SampleResourcePluginTestHelper.revokeAccessPayload;
import static org.opensearch.sample.SampleResourcePluginTestHelper.shareWithPayload;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.resources.ResourceSharingConstants.OPENSEARCH_RESOURCE_SHARING_INDEX;
import static org.opensearch.security.spi.resources.FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with resource sharing enabled but system index protection disabled
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SampleResourcePluginSystemIndexDisabledTests {

    ResourcePluginInfo resourcePluginInfo;
    ResourceSharingExtension resourceSharingExtension;

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .plugin(SampleResourcePlugin.class, PainlessModulePlugin.class)
        .anonymousAuth(true)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN, SHARED_WITH_USER)
        .nodeSettings(Map.of(OPENSEARCH_RESOURCE_SHARING_ENABLED, true))
        .build();

    @Before
    public void setup() {
        resourcePluginInfo = cluster.nodes().getFirst().getInjectable(ResourcePluginInfo.class);
        resourceSharingExtension = new SampleResourceExtension();
    }

    @After
    public void clearIndices() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(RESOURCE_INDEX_NAME);
            client.delete(OPENSEARCH_RESOURCE_SHARING_INDEX);
            resourcePluginInfo.getResourceSharingExtensionsMutable().remove(resourceSharingExtension);
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
        String resourceSharingDocId;
        // create sample resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            String sampleResource = """
                {"name":"sample"}
                """;

            TestRestClient.HttpResponse response = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sampleResource);
            response.assertStatusCode(HttpStatus.SC_OK);

            resourceId = response.getTextFromJsonBody("/message").split(":")[1].trim();
        }

        // Create an entry in resource-sharing index
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // Since test framework doesn't yet allow loading ex tensions we need to create a resource sharing entry manually
            String json = """
                {
                  "source_idx": ".sample_resource_sharing_plugin",
                  "resource_id": "%s",
                  "created_by": {
                    "user": "admin"
                  }
                }
                """.formatted(resourceId);

            TestRestClient.HttpResponse response = client.postJson(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_doc", json);
            assertThat(response.getStatusReason(), containsString("Created"));
            resourceSharingDocId = response.bodyAsJsonNode().get("_id").asText();
            resourcePluginInfo.getResourceSharingExtensionsMutable().add(resourceSharingExtension);

            ResourceSharingClientAccessor.getInstance().setResourceSharingClient(createResourceAccessControlClient(cluster));

            Awaitility.await()
                .alias("Wait until resource data is populated")
                .until(() -> client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId).getStatusCode(), equalTo(200));
            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString("sample"));
            // Wait until resource-sharing entry is successfully created
            Awaitility.await()
                .alias("Wait until resource-sharing data is populated")
                .until(
                    () -> client.get(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_search").bodyAsJsonNode().get("hits").get("hits").size(),
                    equalTo(1)
                );
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
        }

        // resource should be visible to super-admin
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            Awaitility.await()
                .alias("Wait until resource-sharing data is populated")
                .until(
                    () -> client.get(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_search").bodyAsJsonNode().get("hits").get("hits").size(),
                    equalTo(1)
                );
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

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            Awaitility.await()
                .alias("Wait until resource-sharing data is populated")
                .until(
                    () -> client.get(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_search").bodyAsJsonNode().get("hits").get("hits").size(),
                    equalTo(1)
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
                response.bodyAsJsonNode().get("share_with").get(ResourceAccessActionGroups.PLACE_HOLDER).get("users").get(0).asText(),
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

        // resource is still visible to super-admin
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString("sampleUpdated"));
        }

        // revoke share_with_user's access
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.postJson(
                SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + resourceId,
                revokeAccessPayload(SHARED_WITH_USER.getName())
            );
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("share_with").size(), equalTo(0));
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

        // corresponding entry should be removed from resource-sharing index
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // Since test framework doesn't yet allow loading ex tensions we need to delete the resource sharing entry manually
            TestRestClient.HttpResponse response = client.delete(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_doc/" + resourceSharingDocId);
            response.assertStatusCode(HttpStatus.SC_OK);

            Awaitility.await()
                .alias("Wait until resource-sharing data is updated")
                .until(
                    () -> client.get(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_search").bodyAsJsonNode().get("hits").get("hits").size(),
                    equalTo(0)
                );
        }

        // get sample resource with SHARED_WITH_USER
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_NOT_FOUND);
        }

        // get sample resource with admin
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_NOT_FOUND);
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

        // Create an entry in resource-sharing index
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // Since test framework doesn't yet allow loading ex tensions we need to create a resource sharing entry manually
            String json = """
                {
                  "source_idx": "%s",
                  "resource_id": "%s",
                  "created_by": {
                    "user": "admin"
                  }
                }
                """.formatted(RESOURCE_INDEX_NAME, resourceId);

            HttpResponse response = client.postJson(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_doc", json);
            assertThat(response.getStatusReason(), containsString("Created"));
            resourcePluginInfo.getResourceSharingExtensionsMutable().add(resourceSharingExtension);

            ResourceSharingClientAccessor.getInstance().setResourceSharingClient(createResourceAccessControlClient(cluster));

            Awaitility.await()
                .alias("Wait until resource-sharing data is populated")
                .until(
                    () -> client.get(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_search").bodyAsJsonNode().get("hits").get("hits").size(),
                    equalTo(1)
                );
            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(1));
            assertThat(response.getBody(), containsString("sample"));
        }

        // admin will be able to access resource directly since system index protection is disabled, and also via sample plugin
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.get(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // shared_with_user will be able to access resource directly since system index protection is disabled even-though resource is not
        // shared with this user, but cannot access via sample plugin APIs
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse response = client.get(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }

        // Update sample resource shared_with_user will be able to update admin's resource because system index protection is disabled
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            String sampleResourceUpdated = """
                {"name":"sampleUpdated"}
                """;

            TestRestClient.HttpResponse updateResponse = client.postJson(
                RESOURCE_INDEX_NAME + "/_doc/" + resourceId,
                sampleResourceUpdated
            );
            updateResponse.assertStatusCode(HttpStatus.SC_OK);
        }

        // share resource with shared_with user
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Awaitility.await()
                .alias("Wait until resource-sharing data is populated")
                .until(
                    () -> client.get(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_search").bodyAsJsonNode().get("hits").get("hits").size(),
                    equalTo(1)
                );

            HttpResponse response = client.postJson(
                SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + resourceId,
                shareWithPayload(SHARED_WITH_USER.getName())
            );
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(
                response.bodyAsJsonNode().get("share_with").get(ResourceAccessActionGroups.PLACE_HOLDER).get("users").get(0).asText(),
                containsString(SHARED_WITH_USER.getName())
            );
        }

        // shared_with_user will still be able to access resource directly since system index protection is enabled, but can also access via
        // sample plugin
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse response = client.get(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // revoke share_with_user's access
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Awaitility.await()
                .alias("Wait until resource-sharing data is populated")
                .until(
                    () -> client.get(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_search").bodyAsJsonNode().get("hits").get("hits").size(),
                    equalTo(1)
                );
            HttpResponse response = client.postJson(
                SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + resourceId,
                revokeAccessPayload(SHARED_WITH_USER.getName())
            );
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("share_with").size(), equalTo(0));
        }

        // shared_with_user will still be able to access the resource directly but not via sample plugin since access is revoked
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse response = client.get(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }

        // shared_with_user should be able to delete the resource since system index protection is disabled
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse response = client.delete(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }
    }
}
