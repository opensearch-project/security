/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.sample.resource.feature.enabled;

import java.time.Duration;
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
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import tools.jackson.databind.JsonNode;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_CREATE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_UPDATE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.sample.utils.Constants.WORKSPACE_TYPE;
import static org.opensearch.security.api.AbstractApiIntegrationTest.forbidden;
import static org.opensearch.security.api.AbstractApiIntegrationTest.ok;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Exercises the write-path container fan-out: a user with no direct grant can act on a resource because it belongs to a
 * workspace that shares access with them, and loses that access the moment the resource is dissociated. The cluster
 * registers {@code workspace} as a protected type so {@code checkContainers} resolves the workspace's sharing record.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class WorkspaceContainerAccessTests {

    @ClassRule
    public static LocalCluster cluster = newCluster(true, true, List.of(RESOURCE_TYPE, WORKSPACE_TYPE));

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);

    @After
    public void cleanup() {
        api.wipeOutResourceEntries();
    }

    @Test
    public void testWorkspaceContainerGrantsAndRevokesDirectAction() throws Exception {
        final String workspaceId = "ws-team";

        // A resource owned by admin. FULL_ACCESS_USER is neither owner nor shared-with.
        String resId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resId);

        // A workspace whose record shares read access with FULL_ACCESS_USER (workspace_read_only -> sampleresource:get).
        putWorkspaceSharingRecord(workspaceId, "workspace_read_only", FULL_ACCESS_USER.getName());

        // DENY: no direct grant and not yet a member -> the action-level check (hasPermission) forbids GET.
        forbidden(() -> api.getResource(resId, FULL_ACCESS_USER));

        // ALLOW: associate the resource with the workspace. The listener reconciles the sharing record's workspace set;
        // hasPermission then inherits the action from the workspace container.
        setResourceWorkspaces(resId, workspaceId);
        awaitSharingRecordWorkspace(resId, true, workspaceId);
        HttpResponse getResp = ok(() -> api.getResource(resId, FULL_ACCESS_USER));
        assertThat(getResp.getBody(), containsString("sample"));

        // DENY (dissociate): clear the workspace. The record reconciles to empty (removal), so the container grant is
        // gone -- no stale write authorization.
        setResourceWorkspaces(resId);
        awaitSharingRecordWorkspace(resId, false, workspaceId);
        forbidden(() -> api.getResource(resId, FULL_ACCESS_USER));
    }

    @Test
    public void testRapidAssociateThenDissociateConvergesToDenied() throws Exception {
        // Negative control for out-of-order reconciliation: associate then immediately dissociate WITHOUT awaiting the
        // association reconcile. The monotonic guard must ensure the slower association reconcile can never overwrite
        // the newer dissociation, so the resource converges to no-workspace and the direct action is denied.
        final String workspaceId = "ws-race";
        String resId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resId);
        putWorkspaceSharingRecord(workspaceId, "workspace_read_only", FULL_ACCESS_USER.getName());

        setResourceWorkspaces(resId, workspaceId); // associate
        setResourceWorkspaces(resId);              // dissociate immediately, without awaiting the first reconcile

        awaitSharingRecordWorkspace(resId, false, workspaceId);
        forbidden(() -> api.getResource(resId, FULL_ACCESS_USER));
    }

    @Test
    public void testCreateWithWorkspaceThenImmediateClearConvergesToDenied() throws Exception {
        // Negative control for the create race: create a resource already associated with a workspace, then clear it
        // immediately. A reconcile that finds the record not yet written must retry (not no-op), and the clear must
        // win, so the resource converges to no-workspace and the direct action is denied.
        final String workspaceId = "ws-race-create";
        putWorkspaceSharingRecord(workspaceId, "workspace_read_only", FULL_ACCESS_USER.getName());

        String resId = createResourceWithWorkspacesAs(USER_ADMIN, workspaceId);
        setResourceWorkspaces(resId); // clear immediately

        awaitSharingRecordWorkspace(resId, false, workspaceId);
        forbidden(() -> api.getResource(resId, FULL_ACCESS_USER));
    }

    @Test
    public void testOrdinaryUpdateCannotChangeWorkspaceMembership() throws Exception {
        // Trusted-write contract: workspace membership is server-controlled. A user with workspace_read_write (so it
        // can update) must not be able to add another workspace through an ordinary update to acquire that workspace's
        // stronger access level. The sample update route ignores caller-supplied workspaces.
        final String teamWs = "ws-team-rw";
        final String superWs = "ws-super";
        putWorkspaceSharingRecord(teamWs, "workspace_read_write", FULL_ACCESS_USER.getName());
        putWorkspaceSharingRecord(superWs, "workspace_full_access", FULL_ACCESS_USER.getName());

        String resId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resId);
        // Associate only with ws-team-rw through the server-authorized path.
        setResourceWorkspaces(resId, teamWs);
        awaitSharingRecordWorkspace(resId, true, teamWs);

        // FULL_ACCESS_USER (workspace_read_write -> can update) tries to add ws-super via an ordinary update.
        HttpResponse update = updateResourceWithWorkspacesAs(resId, FULL_ACCESS_USER, "escalate", teamWs, superWs);
        update.assertStatusCode(HttpStatus.SC_OK);

        // Membership is unchanged: ws-super was not added, so no escalation to full_access occurred.
        awaitSharingRecordWorkspace(resId, false, superWs);
        awaitSharingRecordWorkspace(resId, true, teamWs);
    }

    // Creates a resource already carrying the given workspaces (create route accepts them; the owner still governs the
    // record). Returns the new resource id.
    private String createResourceWithWorkspacesAs(TestSecurityConfig.User user, String... workspaceIds) {
        String body = "{\"name\":\"sample\",\"resource_type\":\"" + RESOURCE_TYPE + "\",\"workspaces\":" + jsonArray(workspaceIds) + "}";
        try (TestRestClient client = cluster.getRestClient(user)) {
            HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, body);
            resp.assertStatusCode(HttpStatus.SC_OK);
            return resp.getTextFromJsonBody("/message").split(":")[1].trim();
        }
    }

    // Attempts an ordinary update carrying a caller-supplied workspaces field (used to prove it is ignored).
    private HttpResponse updateResourceWithWorkspacesAs(
        String resourceId,
        TestSecurityConfig.User user,
        String newName,
        String... workspaceIds
    ) {
        String body = "{\"name\":\"" + newName + "\",\"workspaces\":" + jsonArray(workspaceIds) + "}";
        try (TestRestClient client = cluster.getRestClient(user)) {
            return client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId, body);
        }
    }

    private static String jsonArray(String... values) {
        StringBuilder arr = new StringBuilder("[");
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                arr.append(",");
            }
            arr.append("\"").append(values[i]).append("\"");
        }
        return arr.append("]").toString();
    }

    // Writes a workspace sharing record directly (mirrors how a real workspace backend materializes collaborators),
    // sharing the given access level with the given user.
    private void putWorkspaceSharingRecord(String workspaceId, String accessLevel, String username) {
        String record = "{"
            + "\"resource_id\":\""
            + workspaceId
            + "\","
            + "\"resource_type\":\""
            + WORKSPACE_TYPE
            + "\","
            + "\"created_by\":{\"user\":\""
            + USER_ADMIN.getName()
            + "\"},"
            + "\"share_with\":{\""
            + accessLevel
            + "\":{\"users\":[\""
            + username
            + "\"]}}"
            + "}";
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse resp = client.putJson(RESOURCE_SHARING_INDEX + "/_doc/" + workspaceId + "?refresh=true", record);
            assertThat(resp.getStatusCode(), equalTo(HttpStatus.SC_CREATED));
        }
    }

    // Sets the resource doc's `workspaces` field to exactly the given ids (empty clears it), as the super admin.
    private void setResourceWorkspaces(String resourceId, String... workspaceIds) {
        StringBuilder arr = new StringBuilder("[");
        for (int i = 0; i < workspaceIds.length; i++) {
            if (i > 0) {
                arr.append(",");
            }
            arr.append("\"").append(workspaceIds[i]).append("\"");
        }
        arr.append("]");
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse resp = client.postJson(
                RESOURCE_INDEX_NAME + "/_update/" + resourceId + "?refresh=true",
                "{\"doc\":{\"workspaces\":" + arr + "}}"
            );
            resp.assertStatusCode(HttpStatus.SC_OK);
        }
    }

    // Waits until the sharing record's `workspaces` set does (or does not) contain the given id.
    private void awaitSharingRecordWorkspace(String resourceId, boolean shouldContain, String workspaceId) {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            Awaitility.await("sharing record for " + resourceId + (shouldContain ? " contains " : " excludes ") + workspaceId)
                .pollInterval(Duration.ofMillis(500))
                .atMost(Duration.ofSeconds(10))
                .untilAsserted(() -> {
                    HttpResponse resp = client.get(RESOURCE_SHARING_INDEX + "/_doc/" + resourceId);
                    resp.assertStatusCode(HttpStatus.SC_OK);
                    JsonNode ws = resp.bodyAsJsonNode().get("_source").get("workspaces");
                    boolean found = false;
                    if (ws != null && ws.isArray()) {
                        for (JsonNode n : ws) {
                            if (workspaceId.equals(n.asString())) {
                                found = true;
                            }
                        }
                    }
                    assertThat(found, equalTo(shouldContain));
                });
        }
    }
}
