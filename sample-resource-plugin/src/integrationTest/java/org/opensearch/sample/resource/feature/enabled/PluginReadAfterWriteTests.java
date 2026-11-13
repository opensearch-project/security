/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature.enabled;

import java.util.ArrayList;
import java.util.List;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.awaitility.Awaitility;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThan;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * With resource sharing enabled, the plugin subject's GET of a resource by id is realtime, so it returns a change
 * that has not been refreshed yet.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class PluginReadAfterWriteTests {

    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);

    @After
    public void cleanup() {
        api.wipeOutResourceEntries();
    }

    /**
     * The sharing record a create writes waits for the next scheduled refresh instead of forcing one, so creating many
     * resources refreshes the sharing index a few times, not once per resource.
     */
    @Test
    public void createsDoNotForceASharingIndexRefreshEach() {
        // The first create makes the sharing index, so its statistics exist to compare against
        awaitPrincipals(api.createSampleResourceAs(FULL_ACCESS_USER));
        int creates = 10;

        long before = refreshes(RESOURCE_SHARING_INDEX);
        List<String> ids = new ArrayList<>();
        for (int i = 0; i < creates; i++) {
            ids.add(api.createSampleResourceAs(FULL_ACCESS_USER));
        }
        ids.forEach(this::awaitPrincipals);
        long refreshed = refreshes(RESOURCE_SHARING_INDEX) - before;

        assertThat("sharing index refreshes for " + creates + " creates: " + refreshed, refreshed, lessThan((long) creates));
    }

    private long refreshes(String index) {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse stats = client.get(index + "/_stats/refresh");
            stats.assertStatusCode(HttpStatus.SC_OK);
            return stats.bodyAsJsonNode().at("/_all/total/refresh/total").asLong();
        }
    }

    private void awaitPrincipals(String resourceId) {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            String query = "{\"query\":{\"ids\":{\"values\":[\"" + resourceId + "\"]}}}";
            Awaitility.await("all_shared_principals written for " + resourceId).untilAsserted(() -> {
                HttpResponse response = client.postJson(RESOURCE_INDEX_NAME + "/_search", query);
                response.assertStatusCode(HttpStatus.SC_OK);
                assertThat(response.bodyAsJsonNode().at("/hits/hits/0/_source/all_shared_principals").size(), greaterThan(0));
            });
        }
    }

    @Test
    public void pluginGetByIdReturnsUnrefreshedUpdate() {
        String resourceId = api.createSampleResourceAs(FULL_ACCESS_USER);
        api.awaitSharingEntry(resourceId, FULL_ACCESS_USER.getName());

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.putJson(RESOURCE_INDEX_NAME + "/_settings", "{\"index.refresh_interval\":\"-1\"}").assertStatusCode(HttpStatus.SC_OK);
            client.postJson(RESOURCE_INDEX_NAME + "/_update/" + resourceId, "{\"doc\":{\"name\":\"renamed\"}}")
                .assertStatusCode(HttpStatus.SC_OK);
        }

        try {
            HttpResponse response = api.getResource(resourceId, FULL_ACCESS_USER);
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString("renamed"));
        } finally {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                client.putJson(RESOURCE_INDEX_NAME + "/_settings", "{\"index.refresh_interval\":null}").assertStatusCode(HttpStatus.SC_OK);
            }
        }
    }
}
