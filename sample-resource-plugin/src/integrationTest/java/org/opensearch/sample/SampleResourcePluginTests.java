package org.opensearch.sample;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.painless.PainlessModulePlugin;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.spi.resources.ResourceAccessScope;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.resources.ResourceSharingConstants.OPENSEARCH_RESOURCE_SHARING_INDEX;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with resource sharing enabled
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SampleResourcePluginTests extends AbstractSampleResourcePluginTests {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .plugin(SampleResourcePlugin.class, PainlessModulePlugin.class)
        .anonymousAuth(true)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN, SHARED_WITH_USER)
        .build();

    @After
    public void clearIndices() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(RESOURCE_INDEX_NAME);
            client.delete(OPENSEARCH_RESOURCE_SHARING_INDEX);
            OpenSearchSecurityPlugin.getResourceIndicesMutable().remove(RESOURCE_INDEX_NAME);
            OpenSearchSecurityPlugin.getResourceProvidersMutable().remove(RESOURCE_INDEX_NAME);
        }
    }

    @Test
    public void testPluginInstalledCorrectly() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse pluginsResponse = client.get("_cat/plugins");
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
            String sampleResource = "{\"name\":\"sample\"}";
            HttpResponse response = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sampleResource);
            response.assertStatusCode(HttpStatus.SC_OK);

            resourceId = response.getTextFromJsonBody("/message").split(":")[1].trim();
        }

        // Create an entry in resource-sharing index
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // Since test framework doesn't yet allow loading ex tensions we need to create a resource sharing entry manually
            String json = String.format(
                "{"
                    + "  \"source_idx\": \".sample_resource_sharing_plugin\","
                    + "  \"resource_id\": \"%s\","
                    + "  \"created_by\": {"
                    + "    \"user\": \"admin\""
                    + "  }"
                    + "}",
                resourceId
            );
            HttpResponse response = client.postJson(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_doc", json);
            assertThat(response.getStatusReason(), containsString("Created"));
            resourceSharingDocId = response.bodyAsJsonNode().get("_id").asText();
            // Also update the in-memory map and list
            OpenSearchSecurityPlugin.getResourceIndicesMutable().add(RESOURCE_INDEX_NAME);
            ResourceProvider provider = new ResourceProvider(
                SampleResource.class.getCanonicalName(),
                RESOURCE_INDEX_NAME,
                new SampleResourceParser()
            );
            OpenSearchSecurityPlugin.getResourceProvidersMutable().put(RESOURCE_INDEX_NAME, provider);

            Thread.sleep(1000);
            response = client.get(SECURITY_RESOURCE_LIST_ENDPOINT + "/" + RESOURCE_INDEX_NAME);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(1));
            assertThat(response.getBody(), containsString("sample"));
        }

        // Update sample resource (admin should be able to update resource)
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            String sampleResourceUpdated = "{\"name\":\"sampleUpdated\"}";
            HttpResponse updateResponse = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId, sampleResourceUpdated);
            updateResponse.assertStatusCode(HttpStatus.SC_OK);
        }

        // resource should be visible to super-admin
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {

            HttpResponse response = client.get(SECURITY_RESOURCE_LIST_ENDPOINT + "/" + RESOURCE_INDEX_NAME);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(1));
            assertThat(response.getBody(), containsString("sampleUpdated"));
        }

        // resource should no longer be visible to shared_with_user
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {

            HttpResponse response = client.get(SECURITY_RESOURCE_LIST_ENDPOINT + "/" + RESOURCE_INDEX_NAME);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(0));
        }

        // shared_with_user should not be able to share admin's resource with itself
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {

            HttpResponse response = client.postJson(SECURITY_RESOURCE_SHARE_ENDPOINT, shareWithPayload(resourceId));
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            assertThat(
                response.bodyAsJsonNode().get("message").asText(),
                containsString("User " + SHARED_WITH_USER.getName() + " is not authorized")
            );
        }

        // share resource with shared_with user
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Thread.sleep(1000);

            HttpResponse response = client.postJson(SECURITY_RESOURCE_SHARE_ENDPOINT, shareWithPayload(resourceId));
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(
                response.bodyAsJsonNode().get("share_with").get(SampleResourceScope.PUBLIC.value()).get("users").get(0).asText(),
                containsString(SHARED_WITH_USER.getName())
            );
        }

        // resource should now be visible to shared_with_user
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse response = client.get(SECURITY_RESOURCE_LIST_ENDPOINT + "/" + RESOURCE_INDEX_NAME);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(1));
            assertThat(response.getBody(), containsString("sampleUpdated"));
        }

        // resource is still visible to super-admin
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse response = client.get(SECURITY_RESOURCE_LIST_ENDPOINT + "/" + RESOURCE_INDEX_NAME);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(1));
            assertThat(response.getBody(), containsString("sampleUpdated"));
        }

        // verify access
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            String verifyAccessPayload = "{\"resource_id\":\""
                + resourceId
                + "\",\"resource_index\":\""
                + RESOURCE_INDEX_NAME
                + "\",\"scope\":\""
                + ResourceAccessScope.PUBLIC
                + "\"}";
            HttpResponse response = client.postJson(SECURITY_RESOURCE_VERIFY_ENDPOINT, verifyAccessPayload);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("has_permission").asBoolean(), equalTo(true));
        }

        // shared_with user should not be able to revoke access to admin's resource
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse response = client.postJson(SECURITY_RESOURCE_REVOKE_ENDPOINT, revokeAccessPayload(resourceId));
            response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            assertThat(
                response.bodyAsJsonNode().get("message").asText(),
                containsString("User " + SHARED_WITH_USER.getName() + " is not authorized")
            );
        }

        // revoke share_with_user's access
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Thread.sleep(1000);
            HttpResponse response = client.postJson(SECURITY_RESOURCE_REVOKE_ENDPOINT, revokeAccessPayload(resourceId));
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("share_with"), nullValue());
        }

        // verify access - share_with_user should no longer have access to admin's resource
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            String verifyAccessPayload = "{\"resource_id\":\""
                + resourceId
                + "\",\"resource_index\":\""
                + RESOURCE_INDEX_NAME
                + "\",\"scope\":\""
                + ResourceAccessScope.PUBLIC
                + "\"}";
            HttpResponse response = client.postJson(SECURITY_RESOURCE_VERIFY_ENDPOINT, verifyAccessPayload);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("has_permission").asBoolean(), equalTo(false));
        }

        // delete sample resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // corresponding entry should be removed from resource-sharing index
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // Since test framework doesn't yet allow loading ex tensions we need to delete the resource sharing entry manually
            HttpResponse response = client.delete(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_doc/" + resourceSharingDocId);
            assertThat(response.getStatusReason(), containsString("OK"));

            Thread.sleep(1000);
            response = client.get(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_search");
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString("hits\":[]"));
        }
    }

    @Test
    public void testDLSRestrictionForResourceByDirectlyUpdatingTheResourceIndex() throws Exception {
        String resourceId;
        // create sample resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            String sampleResource = "{\"name\":\"sample\"}";
            HttpResponse response = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sampleResource);
            response.assertStatusCode(HttpStatus.SC_CREATED);

            resourceId = response.bodyAsJsonNode().get("_id").asText();
        }

        // Create an entry in resource-sharing index
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // Since test framework doesn't yet allow loading ex tensions we need to create a resource sharing entry manually
            String json = String.format(
                "{"
                    + "  \"source_idx\": \".sample_resource_sharing_plugin\","
                    + "  \"resource_id\": \"%s\","
                    + "  \"created_by\": {"
                    + "    \"user\": \"admin\""
                    + "  }"
                    + "}",
                resourceId
            );
            HttpResponse response = client.postJson(OPENSEARCH_RESOURCE_SHARING_INDEX + "/_doc", json);
            assertThat(response.getStatusReason(), containsString("Created"));
            // Also update the in-memory map and list
            OpenSearchSecurityPlugin.getResourceIndicesMutable().add(RESOURCE_INDEX_NAME);
            ResourceProvider provider = new ResourceProvider(
                SampleResource.class.getCanonicalName(),
                RESOURCE_INDEX_NAME,
                new SampleResourceParser()
            );
            OpenSearchSecurityPlugin.getResourceProvidersMutable().put(RESOURCE_INDEX_NAME, provider);

            Thread.sleep(1000);
        }

        // resource is still visible to super-admin
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {

            HttpResponse response = client.postJson(RESOURCE_INDEX_NAME + "/_search", "{\"query\" : {\"match_all\" : {}}}");
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("hits").get("hits").size(), equalTo(1));
            assertThat(response.getBody(), containsString("sample"));
        }

        String updatePayload = "{" + "\"doc\": {" + "\"name\": \"sampleUpdated\"" + "}" + "}";

        // Update sample resource with shared_with user. This will fail since the resource has not been shared
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse updateResponse = client.postJson(RESOURCE_INDEX_NAME + "/_update/" + resourceId, updatePayload);
            // it will show not found since the resource is not visible to shared_with_user
            updateResponse.assertStatusCode(HttpStatus.SC_NOT_FOUND);
        }

        // Admin is still allowed to update its own resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse updateResponse = client.postJson(RESOURCE_INDEX_NAME + "/_update/" + resourceId, updatePayload);
            // it will show not found since the resource is not visible to shared_with_user
            updateResponse.assertStatusCode(HttpStatus.SC_OK);
            assertThat(updateResponse.bodyAsJsonNode().get("_shards").get("successful").asInt(), equalTo(1));
        }

        // Verify that share_with user does not have access to the resource
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse getResponse = client.get(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            // it will show not found since the resource is not visible to shared_with_user
            getResponse.assertStatusCode(HttpStatus.SC_NOT_FOUND);
        }

        // share the resource with shared_with_user
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.postJson(SECURITY_RESOURCE_SHARE_ENDPOINT, shareWithPayload(resourceId));
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // Verify that share_with user now has access to the resource
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            HttpResponse getResponse = client.get(RESOURCE_INDEX_NAME + "/_doc/" + resourceId);
            // it will show not found since the resource is not visible to shared_with_user
            getResponse.assertStatusCode(HttpStatus.SC_OK);
            assertThat(getResponse.getBody(), containsString("sampleUpdated"));
        }
    }

}
