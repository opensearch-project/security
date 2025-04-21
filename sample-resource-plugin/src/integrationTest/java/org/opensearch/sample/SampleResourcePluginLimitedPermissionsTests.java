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
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.painless.PainlessModulePlugin;
import org.opensearch.sample.resource.client.ResourceSharingClientAccessor;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.resources.ResourceSharingConstants.OPENSEARCH_RESOURCE_SHARING_INDEX;
import static org.opensearch.security.spi.resources.FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with resource sharing enabled and system index protection enabled
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SampleResourcePluginLimitedPermissionsTests extends AbstractSampleResourcePluginFeatureEnabledTests {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .plugin(SampleResourcePlugin.class, PainlessModulePlugin.class)
        .anonymousAuth(true)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN, SHARED_WITH_USER_LIMITED_PERMISSIONS)
        .nodeSettings(Map.of(SECURITY_SYSTEM_INDICES_ENABLED_KEY, true, OPENSEARCH_RESOURCE_SHARING_ENABLED, true))
        .build();

    @Override
    protected LocalCluster getLocalCluster() {
        return cluster;
    }

    @Override
    protected TestSecurityConfig.User getSharedUser() {
        return SHARED_WITH_USER_LIMITED_PERMISSIONS;
    }

    @Test
    public void testAccessWithLimitedIP() throws Exception {
        String resourceId;
        // create sample resource
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_LIMITED_PERMISSIONS)) {
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
                    "user": "%s"
                  }
                }
                """.formatted(RESOURCE_INDEX_NAME, resourceId, SHARED_WITH_USER_LIMITED_PERMISSIONS.getName());

            HttpResponse response = client.postJson(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_doc", json);
            assertThat(response.getStatusReason(), containsString("Created"));

            // Also update the in-memory map and get
            resourcePluginInfo.getResourceIndicesMutable().add(RESOURCE_INDEX_NAME);
            ResourceProvider provider = new ResourceProvider(SampleResource.class.getCanonicalName(), RESOURCE_INDEX_NAME);
            resourcePluginInfo.getResourceProvidersMutable().put(RESOURCE_INDEX_NAME, provider);

            ResourceSharingClientAccessor.setResourceSharingClient(createResourceAccessControlClient(cluster));

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

        // user should be able to get its own resource as it has get API access
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_LIMITED_PERMISSIONS)) {
            HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // Update user's sample resource
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_LIMITED_PERMISSIONS)) {
            String sampleResourceUpdated = """
                {"name":"sampleUpdated"}
                """;

            HttpResponse updateResponse = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId, sampleResourceUpdated);
            // cannot update because this user doesnt have access to update API
            updateResponse.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            assertThat(
                updateResponse.bodyAsJsonNode().get("error").get("root_cause").get(0).get("reason").asText(),
                containsString(
                    "no permissions for [cluster:admin/sample-resource-plugin/update] and User [name=resource_sharing_test_user_limited_perms, backend_roles=[], requestedTenant=null]"
                )
            );
        }

        // User admin should not be able to update, since resource is not shared with it
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            String sampleResourceUpdated = """
                {"name":"sampleUpdated"}
                """;

            HttpResponse updateResponse = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId, sampleResourceUpdated);
            // cannot update because this user doesnt have access to the resource
            updateResponse.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }

        // Super admin can update the resource
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            String sampleResourceUpdated = """
                {"name":"sampleUpdated"}
                """;

            HttpResponse updateResponse = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId, sampleResourceUpdated);
            // cannot update because this user doesnt have access to update API
            updateResponse.assertStatusCode(HttpStatus.SC_OK);
            assertThat(updateResponse.getBody(), containsString("sample"));
        }

        // share resource with admin
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_LIMITED_PERMISSIONS)) {
            HttpResponse response = client.postJson(
                SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + resourceId,
                shareWithPayload(USER_ADMIN.getName())
            );

            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // admin is able to access resource now
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // revoke admin's access
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_LIMITED_PERMISSIONS)) {
            HttpResponse response = client.postJson(
                SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + resourceId,
                revokeAccessPayload(USER_ADMIN.getName())
            );

            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // admin can no longer access the resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }

        // delete sample resource
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_LIMITED_PERMISSIONS)) {
            HttpResponse response = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);

            // cannot delete because this user doesnt have access to delete API
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            assertThat(
                response.bodyAsJsonNode().get("error").get("root_cause").get(0).get("reason").asText(),
                containsString(
                    "no permissions for [cluster:admin/sample-resource-plugin/delete] and User [name=resource_sharing_test_user_limited_perms, backend_roles=[], requestedTenant=null]"
                )
            );
        }

        // User admin should not be able to delete share_with_user's resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);

            // cannot delete because user admin doesn't have access to resource
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }

        // Super admin can delete the resource
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse response = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);

            response.assertStatusCode(HttpStatus.SC_OK);
        }
    }
}
