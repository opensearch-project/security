/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.disabled;

import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.painless.PainlessModulePlugin;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_CREATE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_DELETE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_REVOKE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_SHARE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_UPDATE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.revokeAccessPayload;
import static org.opensearch.sample.resource.TestHelper.sampleReadOnlyAG;
import static org.opensearch.sample.resource.TestHelper.shareWithPayload;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * This class defines a test scenario where security plugin is disabled
 * It checks access through sample plugin as well as through direct security API calls
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SecurityDisabledTests {

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
            String sampleResource = """
                {"name":"sample"}
                """;

            TestRestClient.HttpResponse response = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sampleResource);
            response.assertStatusCode(HttpStatus.SC_OK);
            String resourceId = response.getTextFromJsonBody("/message").split(":")[1].trim();

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT);
            response.assertStatusCode(HttpStatus.SC_OK);

            response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);

            String sampleResourceUpdated = """
                {"name":"sampleUpdated"}
                """;

            response = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId, sampleResourceUpdated);
            response.assertStatusCode(HttpStatus.SC_OK);

            response = client.postJson(
                SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + resourceId,
                shareWithPayload(USER_ADMIN.getName(), sampleReadOnlyAG.name())
            );
            assertNotImplementedResponse(response);

            response = client.postJson(
                SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + resourceId,
                revokeAccessPayload(USER_ADMIN.getName(), sampleReadOnlyAG.name())
            );
            assertNotImplementedResponse(response);

            response = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(HttpStatus.SC_OK);

        }
    }

    private void assertNotImplementedResponse(TestRestClient.HttpResponse response) {
        response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
        assertThat(response.getTextFromJsonBody("/error"), containsString("no handler found for uri"));
    }
}
