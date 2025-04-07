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
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.painless.PainlessModulePlugin;
import org.opensearch.sample.resource.client.ResourceSharingClientAccessor;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.spi.resources.ResourceAccessActionGroups;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.sample.utils.Constants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.resources.ResourceSharingConstants.OPENSEARCH_RESOURCE_SHARING_INDEX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with resource sharing enabled and system index protection enabled
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SampleResourcePluginTests extends AbstractSampleResourcePluginFeatureEnabledTests {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .plugin(SampleResourcePlugin.class, PainlessModulePlugin.class)
        .anonymousAuth(true)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN, SHARED_WITH_USER)
        .nodeSettings(Map.of(SECURITY_SYSTEM_INDICES_ENABLED_KEY, true, OPENSEARCH_RESOURCE_SHARING_ENABLED, true))
        .build();

    @Override
    protected LocalCluster getLocalCluster() {
        return cluster;
    }

    @Override
    protected TestSecurityConfig.User getSharedUser() {
        return SHARED_WITH_USER;
    }

    @Test
    public void testDirectAccess() throws Exception {
        ResourcePluginInfo resourcePluginInfo = cluster.nodes().getFirst().getInjectable(ResourcePluginInfo.class);

        String resourceId;
        // create sample resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            String sampleResource = "{\"name\":\"sample\"}";
            HttpResponse response = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sampleResource);
            response.assertStatusCode(HttpStatus.SC_OK);

            resourceId = response.getTextFromJsonBody("/message").split(":")[1].trim();
            Thread.sleep(1000);
        }

        // Create an entry in resource-sharing index
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // Since test framework doesn't yet allow loading ex tensions we need to create a resource sharing entry manually
            String json = String.format(
                "{"
                    + "  \"source_idx\": \""
                    + RESOURCE_INDEX_NAME
                    + "\","
                    + "  \"resource_id\": \"%s\","
                    + "  \"created_by\": {"
                    + "    \"user\": \"admin\""
                    + "  }"
                    + "}",
                resourceId
            );
            HttpResponse response = client.postJson(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_doc", json);
            assertThat(response.getStatusReason(), containsString("Created"));
            // Also update the in-memory map and get
            resourcePluginInfo.getResourceIndicesMutable().add(RESOURCE_INDEX_NAME);
            ResourceProvider provider = new ResourceProvider(
                SampleResource.class.getCanonicalName(),
                RESOURCE_INDEX_NAME,
                new SampleResourceParser()
            );
            resourcePluginInfo.getResourceProvidersMutable().put(RESOURCE_INDEX_NAME, provider);

            ResourceSharingClientAccessor.setResourceSharingClient(createResourceAccessControlClient(cluster));

            Thread.sleep(1000);
            response = client.get(SECURITY_RESOURCE_LIST_ENDPOINT + "/" + RESOURCE_INDEX_NAME);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(1));
            assertThat(response.getBody(), containsString("sample"));
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
            String sampleResourceUpdated = "{\"name\":\"sampleUpdated\"}";
            TestRestClient.HttpResponse updateResponse = client.postJson(
                RESOURCE_INDEX_NAME + "/_doc/" + resourceId,
                sampleResourceUpdated
            );
            updateResponse.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }

        // share resource with shared_with user
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Thread.sleep(1000);

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

        // shared_with_user should not be able to access resource directly since system index protection is enabled, but can access via
        // sample plugin
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse response = client.get(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_NOT_FOUND);

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // revoke share_with_user's access
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Thread.sleep(1000);
            HttpResponse response = client.postJson(
                SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + resourceId,
                revokeAccessPayload(SHARED_WITH_USER.getName())
            );
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("share_with").size(), equalTo(0));
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
