package org.opensearch.sample;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.painless.PainlessModulePlugin;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.spi.resources.ResourceAccessScope;
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
import static org.opensearch.sample.utils.Constants.SAMPLE_RESOURCE_PLUGIN_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.resources.ResourceSharingConstants.OPENSEARCH_RESOURCE_SHARING_INDEX;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with security enabled
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SampleResourcePluginTests {

    public final static TestSecurityConfig.User SHARED_WITH_USER = new TestSecurityConfig.User("resource_sharing_test_user").roles(
        new TestSecurityConfig.Role("shared_role").indexPermissions("*").on("*").clusterPermissions("*")
    );

    private static final String SAMPLE_RESOURCE_CREATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/create";
    private static final String SAMPLE_RESOURCE_UPDATE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/update";
    private static final String SAMPLE_RESOURCE_DELETE_ENDPOINT = SAMPLE_RESOURCE_PLUGIN_PREFIX + "/delete";
    private static final String SECURITY_RESOURCE_LIST_ENDPOINT = PLUGINS_PREFIX + "/resources/list";
    private static final String SECURITY_RESOURCE_SHARE_ENDPOINT = PLUGINS_PREFIX + "/resources/share";
    private static final String SECURITY_RESOURCE_VERIFY_ENDPOINT = PLUGINS_PREFIX + "/resources/verify_access";
    private static final String SECURITY_RESOURCE_REVOKE_ENDPOINT = PLUGINS_PREFIX + "/resources/revoke";

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .plugin(SampleResourcePlugin.class, PainlessModulePlugin.class)
        .anonymousAuth(true)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN, SHARED_WITH_USER)
        .build();

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
            Thread.sleep(2000);
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
            assertThat(response.bodyAsJsonNode().get("resources").size(), equalTo(1));
            assertThat(response.getBody(), containsString("sample"));
        }

        // Update sample resource (admin should be able to update resource)
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Thread.sleep(1000);

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

            String shareWithPayload = "{"
                + "\"resource_id\":\""
                + resourceId
                + "\","
                + "\"resource_index\":\""
                + RESOURCE_INDEX_NAME
                + "\","
                + "\"share_with\":{"
                + "\""
                + SampleResourceScope.PUBLIC.value()
                + "\":{"
                + "\"users\": [\""
                + SHARED_WITH_USER.getName()
                + "\"]"
                + "}"
                + "}"
                + "}";
            HttpResponse response = client.postJson(SECURITY_RESOURCE_SHARE_ENDPOINT, shareWithPayload);
            response.assertStatusCode(HttpStatus.SC_INTERNAL_SERVER_ERROR);
            assertThat(response.bodyAsJsonNode().toString(), containsString("User " + SHARED_WITH_USER.getName() + " is not authorized"));
            // TODO these tests must check for unauthorized instead of internal-server-error
            // response.assertStatusCode(HttpStatus.SC_UNAUTHORIZED);
            // assertThat(response.bodyAsJsonNode().get("message").asText(), containsString("User is not authorized"));
        }

        // share resource with shared_with user
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Thread.sleep(1000);
            String shareWithPayload = "{"
                + "\"resource_id\":\""
                + resourceId
                + "\","
                + "\"resource_index\":\""
                + RESOURCE_INDEX_NAME
                + "\","
                + "\"share_with\":{"
                + "\""
                + SampleResourceScope.PUBLIC.value()
                + "\":{"
                + "\"users\": [\""
                + SHARED_WITH_USER.getName()
                + "\"]"
                + "}"
                + "}"
                + "}";
            HttpResponse response = client.postJson(SECURITY_RESOURCE_SHARE_ENDPOINT, shareWithPayload);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().get("message").asText(), containsString(resourceId));
        }

        // resource should now be visible to shared_with_user
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            Thread.sleep(3000); // allow changes to be reflected
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
            Thread.sleep(1000);
            String verifyAccessPayload = "{\"resource_id\":\""
                + resourceId
                + "\",\"resource_index\":\""
                + RESOURCE_INDEX_NAME
                + "\",\"scope\":\""
                + ResourceAccessScope.PUBLIC
                + "\"}";
            HttpResponse response = client.getWithJsonBody(SECURITY_RESOURCE_VERIFY_ENDPOINT, verifyAccessPayload);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString("User has requested scope " + ResourceAccessScope.PUBLIC + " access"));
        }

        // shared_with user should not be able to revoke access to admin's resource
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            Thread.sleep(1000);
            String revokePayload = "{"
                + "\"resource_id\": \""
                + resourceId
                + "\","
                + "\"resource_index\": \""
                + RESOURCE_INDEX_NAME
                + "\","
                + "\"entities\": {"
                + "\"users\": [\""
                + SHARED_WITH_USER.getName()
                + "\"]"
                + "},"
                + "\"scopes\": [\""
                + ResourceAccessScope.PUBLIC
                + "\"]"
                + "}";

            HttpResponse response = client.postJson(SECURITY_RESOURCE_REVOKE_ENDPOINT, revokePayload);
            response.assertStatusCode(HttpStatus.SC_INTERNAL_SERVER_ERROR);
            assertThat(response.bodyAsJsonNode().toString(), containsString("User " + SHARED_WITH_USER.getName() + " is not authorized"));
            // TODO these tests must check for unauthorized instead of internal-server-error
            // response.assertStatusCode(HttpStatus.SC_UNAUTHORIZED);
            // assertThat(response.bodyAsJsonNode().get("message").asText(), containsString("User is not authorized"));
        }

        // revoke share_wit_user's access
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Thread.sleep(1000);
            String revokePayload = "{"
                + "\"resource_id\": \""
                + resourceId
                + "\","
                + "\"resource_index\": \""
                + RESOURCE_INDEX_NAME
                + "\","
                + "\"entities\": {"
                + "\"users\": [\""
                + SHARED_WITH_USER.getName()
                + "\"]"
                + "},"
                + "\"scopes\": [\""
                + ResourceAccessScope.PUBLIC
                + "\"]"
                + "}";

            HttpResponse response = client.postJson(SECURITY_RESOURCE_REVOKE_ENDPOINT, revokePayload);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.bodyAsJsonNode().toString(), containsString("Resource " + resourceId + " access revoked successfully."));
        }

        // verify access - share_with_user should no longer have access to admin's resource
        try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER)) {
            Thread.sleep(1000);
            String verifyAccessPayload = "{\"resource_id\":\""
                + resourceId
                + "\",\"resource_index\":\""
                + RESOURCE_INDEX_NAME
                + "\",\"scope\":\""
                + ResourceAccessScope.PUBLIC
                + "\"}";
            HttpResponse response = client.getWithJsonBody(SECURITY_RESOURCE_VERIFY_ENDPOINT, verifyAccessPayload);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString("User does not have requested scope " + ResourceAccessScope.PUBLIC + " access"));
        }

        // delete sample resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);
            Thread.sleep(2000);
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

    // TODO add test case for updating the resource directly
}
