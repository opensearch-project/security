/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup;

import java.time.Duration;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.awaitility.Awaitility;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.sample.resource.TestUtils;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_GROUP_READ_ONLY;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.utils.Constants.RESOURCE_GROUP_TYPE;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.security.api.AbstractApiIntegrationTest.forbidden;
import static org.opensearch.security.api.AbstractApiIntegrationTest.ok;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Tests sharing-entry creation for resources written WITHOUT an authenticated
 * user in the thread context — the situation plugins are in when they index
 * resource documents under a genuinely user-less subject, e.g. scheduled jobs
 * running under job-scheduler or system/provisioning-context writes.
 *
 * (Note: request-driven writes that stash-then-restore the caller's context —
 * such as reporting's on-demand report instances — do carry the authenticated
 * user, so postIndex attributes them normally; they are not the user-less case
 * exercised here.)
 *
 * Child resources (provider declares parentType/parentIdField) must still
 * receive a sharing entry, inheriting ownership from the parent's record.
 * Parent-less resources cannot be attributed and must be skipped.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SystemContextChildResourceTests {

    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);
    private String resourceGroupId;

    @Before
    public void setup() {
        resourceGroupId = api.createSampleResourceGroupAs(USER_ADMIN);
        api.awaitSharingEntry(resourceGroupId); // parent sharing entry exists
    }

    @After
    public void cleanup() {
        api.wipeOutResourceEntries();
    }

    /** Indexes a resource document via the internal node client: no authenticated user in context. */
    private String indexResourceWithoutUser(String docJson) {
        Client client = cluster.getInternalNodeClient();
        IndexRequest request = new IndexRequest(RESOURCE_INDEX_NAME).source(docJson, XContentType.JSON)
            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        IndexResponse response = client.index(request).actionGet();
        return response.getId();
    }

    @Test
    public void testChildResourceWrittenWithoutUserInheritsParentSharing() throws Exception {
        String childId = indexResourceWithoutUser(
            "{\"group_id\":\"" + resourceGroupId + "\", \"name\":\"system-created\",\"resource_type\":\"" + RESOURCE_TYPE + "\"}"
        );

        // A sharing entry must be created despite the absent user, attributed
        // to the parent's owner and linked to the parent.
        api.awaitSharingEntry(childId, USER_ADMIN.getName());
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse entry = client.get(RESOURCE_SHARING_INDEX + "/_doc/" + childId);
            entry.assertStatusCode(200);
            assertThat(entry.getBody(), containsString("\"parent_id\":\"" + resourceGroupId + "\""));
            assertThat(entry.getBody(), containsString("\"parent_type\":\"" + RESOURCE_GROUP_TYPE + "\""));
            assertThat(entry.getBody(), containsString(USER_ADMIN.getName()));
        }

        // Owner of the parent has access to the child through the inherited entry
        ok(() -> api.getResource(childId, USER_ADMIN));

        // A user without any share sees neither parent nor child
        forbidden(() -> api.getResource(childId, FULL_ACCESS_USER));

        // Sharing the parent group grants access to the system-created child
        ok(() -> api.shareResourceGroup(resourceGroupId, USER_ADMIN, FULL_ACCESS_USER, SAMPLE_GROUP_READ_ONLY));
        ok(() -> api.getResource(childId, FULL_ACCESS_USER));
    }

    @Test
    public void testParentlessResourceWrittenWithoutUserIsSkipped() throws Exception {
        // A resource-group has no parent declared: with no user in context there
        // is nothing to attribute the sharing entry to, so none must be created.
        String orphanId = indexResourceWithoutUser("{\"name\":\"system-created-group\",\"resource_type\":\"" + RESOURCE_GROUP_TYPE + "\"}");

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            Awaitility.await("sharing entry must not appear for parent-less user-less resource " + orphanId)
                .pollDelay(Duration.ofSeconds(2))
                .pollInterval(Duration.ofMillis(500))
                .atMost(Duration.ofSeconds(4))
                .untilAsserted(() -> {
                    TestRestClient.HttpResponse response = client.get(RESOURCE_SHARING_INDEX + "/_doc/" + orphanId);
                    response.assertStatusCode(404);
                });
        }
    }

    @Test
    public void testChildResourceWithMissingParentRecordIsSkipped() throws Exception {
        // Child pointing at a non-existent parent: no record to inherit from.
        String childId = indexResourceWithoutUser(
            "{\"group_id\":\"no-such-group\", \"name\":\"system-created\",\"resource_type\":\"" + RESOURCE_TYPE + "\"}"
        );

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            Awaitility.await("sharing entry must not appear for child with missing parent " + childId)
                .pollDelay(Duration.ofSeconds(2))
                .pollInterval(Duration.ofMillis(500))
                .atMost(Duration.ofSeconds(4))
                .untilAsserted(() -> {
                    TestRestClient.HttpResponse response = client.get(RESOURCE_SHARING_INDEX + "/_doc/" + childId);
                    response.assertStatusCode(404);
                });
        }
    }
}
