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
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
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
     * A create writes its sharing record without forcing a refresh, so creating many resources barely refreshes the
     * sharing index. Its all_shared_principals write still forces one on the resource index, as the plugin's create does.
     */
    @Test
    public void createsForceNoSharingIndexRefresh() {
        // The first create makes the sharing index, so its settings and statistics exist
        api.awaitPrincipals(api.createSampleResourceAs(FULL_ACCESS_USER));
        int creates = 10;

        // With scheduled refreshes off, every refresh counted below is one a write forced
        setRefreshInterval("-1");
        long sharing;
        long resource;
        try {
            long sharingBefore = primaryRefreshes(RESOURCE_SHARING_INDEX);
            long resourceBefore = primaryRefreshes(RESOURCE_INDEX_NAME);
            List<String> ids = new ArrayList<>();
            for (int i = 0; i < creates; i++) {
                ids.add(api.createSampleResourceAs(FULL_ACCESS_USER));
            }
            ids.forEach(api::awaitPrincipals);
            sharing = primaryRefreshes(RESOURCE_SHARING_INDEX) - sharingBefore;
            resource = primaryRefreshes(RESOURCE_INDEX_NAME) - resourceBefore;
        } finally {
            setRefreshInterval(null);
        }

        String counts = creates + " creates refreshed the sharing index " + sharing + " times and the resource index " + resource;
        // A record write that forced a refresh would cost one refresh per create
        assertThat(counts, sharing, lessThan((long) creates));
        // One forced refresh for the plugin's own create and one for the all_shared_principals write
        assertThat(counts, resource, lessThanOrEqualTo(2L * creates));
    }

    private void setRefreshInterval(String interval) {
        String body = "{\"index.refresh_interval\":" + (interval == null ? "null" : "\"" + interval + "\"") + "}";
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.putJson(RESOURCE_INDEX_NAME + "," + RESOURCE_SHARING_INDEX + "/_settings", body).assertStatusCode(HttpStatus.SC_OK);
        }
    }

    // Primaries only, so the count does not depend on how many replicas the test cluster allocates
    private long primaryRefreshes(String index) {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse stats = client.get(index + "/_stats/refresh");
            stats.assertStatusCode(HttpStatus.SC_OK);
            return stats.bodyAsJsonNode().at("/_all/primaries/refresh/total").asLong();
        }
    }

    /**
     * A new resource's field write starts from the version its create produced and from the record just created, so the
     * create reads the resource document only inside its own updates.
     */
    @Test
    public void createReadsNoResourceDocumentBeforeItsFieldWrite() {
        // The first create makes the resource index, so the statistics exist to compare against
        api.awaitPrincipals(api.createSampleResourceAs(FULL_ACCESS_USER));

        long before = api.resourceDocumentGets();
        List<String> ids = List.of(api.createSampleResourceAs(FULL_ACCESS_USER), api.createSampleResourceAs(FULL_ACCESS_USER));
        ids.forEach(api::awaitPrincipals);

        // Each field write is an update, which reads the document itself, and its restore is a NOOP update that does too
        long reads = api.resourceDocumentGets() - before;
        assertThat("resource document GETs during create: " + reads, reads, lessThanOrEqualTo(2L * ids.size()));
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
