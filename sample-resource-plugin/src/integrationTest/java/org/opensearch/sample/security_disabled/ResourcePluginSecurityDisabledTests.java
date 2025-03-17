/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.security_disabled;

import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.painless.PainlessModulePlugin;
import org.opensearch.rest.RestRequest;
import org.opensearch.sample.AbstractSampleResourcePluginTests;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * This class defines a test scenario where security plugin is disabled
 * It checks access through sample plugin as well as through direct security API calls
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ResourcePluginSecurityDisabledTests extends AbstractSampleResourcePluginTests {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .plugin(SampleResourcePlugin.class, PainlessModulePlugin.class)
        .loadConfigurationIntoIndex(false)
        .nodeSettings(Map.of("plugins.security.disabled", true, "plugins.security.ssl.http.enabled", false))
        .build();

    @After
    public void clearIndices() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            client.delete(RESOURCE_INDEX_NAME);
        }
    }

    @Test
    public void testPluginInstalledCorrectly() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            TestRestClient.HttpResponse pluginsResponse = client.get("_cat/plugins");
            // security plugin is simply disabled but it will still be present in
            assertThat(pluginsResponse.getBody(), containsString("org.opensearch.security.OpenSearchSecurityPlugin"));
            assertThat(pluginsResponse.getBody(), containsString("org.opensearch.sample.SampleResourcePlugin"));
        }
    }

    @Test
    public void testSamplePluginAPIs() {
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            String sampleResource = "{\"name\":\"sample\"}";
            TestRestClient.HttpResponse response = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sampleResource);
            response.assertStatusCode(HttpStatus.SC_OK);
            String resourceId = response.getTextFromJsonBody("/message").split(":")[1].trim();
            ;

            // in sample plugin implementation, get all API is checked against
            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT);
            response.assertStatusCode(HttpStatus.SC_OK);

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);

            String sampleResourceUpdated = "{\"name\":\"sampleUpdated\"}";
            response = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId, sampleResourceUpdated);
            response.assertStatusCode(HttpStatus.SC_OK);

            response = client.postJson(SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + resourceId, shareWithPayload(USER_ADMIN.getName()));
            assertNotImplementedResponse(response);

            response = client.postJson(SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + resourceId, revokeAccessPayload(USER_ADMIN.getName()));
            assertNotImplementedResponse(response);

            response = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);

        }
    }

    @Test
    public void testSecurityResourceAPIs() {
        // APIs are not implemented since security plugin is disabled
        try (TestRestClient client = cluster.getSecurityDisabledRestClient()) {
            TestRestClient.HttpResponse response = client.get(SECURITY_RESOURCE_LIST_ENDPOINT + "/" + RESOURCE_INDEX_NAME);
            assertBadResponse(response, SECURITY_RESOURCE_LIST_ENDPOINT + "/" + RESOURCE_INDEX_NAME, RestRequest.Method.GET.name());

            String samplePayload = "{ \"resource_index\": \"" + RESOURCE_INDEX_NAME + "\"}";
            response = client.postJson(SECURITY_RESOURCE_VERIFY_ENDPOINT, samplePayload);
            assertBadResponse(response, SECURITY_RESOURCE_VERIFY_ENDPOINT, RestRequest.Method.POST.name());

            response = client.postJson(SECURITY_RESOURCE_SHARE_ENDPOINT, samplePayload);
            assertBadResponse(response, SECURITY_RESOURCE_SHARE_ENDPOINT, RestRequest.Method.POST.name());

            response = client.postJson(SECURITY_RESOURCE_REVOKE_ENDPOINT, samplePayload);
            assertBadResponse(response, SECURITY_RESOURCE_REVOKE_ENDPOINT, RestRequest.Method.POST.name());

        }
    }

    private void assertNotImplementedResponse(TestRestClient.HttpResponse response) {
        response.assertStatusCode(HttpStatus.SC_NOT_IMPLEMENTED);
        assertThat(response.getTextFromJsonBody("/error/reason"), containsString("Security Plugin is disabled"));
    }

    private void assertBadResponse(TestRestClient.HttpResponse response, String uri, String method) {
        response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
        assertThat(
            response.getTextFromJsonBody("/error"),
            containsString("no handler found for uri [/" + uri + "] and method [" + method + "]")
        );
    }
}
