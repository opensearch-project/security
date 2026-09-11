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

package org.opensearch.security.api;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import tools.jackson.databind.JsonNode;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * End-to-end coverage for {@code wait_for_completion} on Security configuration write APIs
 * (issue <a href="https://github.com/opensearch-project/security/issues/6337">#6337</a>).
 *
 * <p>Covers, per acceptance criterion:
 * <ul>
 *   <li>synchronous success (backwards compatibility — parameter omitted or set to {@code true}),</li>
 *   <li>synchronous failure (invalid body still surfaces as 400 even when the async param is set),</li>
 *   <li>asynchronous success (task-id response and task lookup),</li>
 *   <li>task cancellation is refused (non-cancellable by design).</li>
 * </ul>
 *
 * <p>Async is exercised against every endpoint that opts in to {@code supportsAsync()} in this PR:
 * Roles, RolesMapping, InternalUsers, Tenants, Audit. Roles is used as the representative for
 * the sync/back-compat cases since the payload is smaller than InternalUsers or Audit.
 */
public class WaitForCompletionRestApiIntegrationTest extends AbstractApiIntegrationTest {

    @ClassRule
    public static LocalCluster localCluster = clusterBuilder().build();

    // ---------- helpers ----------

    private static final String VALID_ROLE_BODY = """
        {
          "cluster_permissions": ["cluster_composite_ops_ro"],
          "index_permissions": [
            { "index_patterns": ["logs-*"], "allowed_actions": ["read"] }
          ]
        }
        """;

    private static final String INVALID_ROLE_BODY = """
        {
          "cluster_permissions": ["cluster_composite_ops_ro"],
          "unknown_field": true
        }
        """;

    private static final String VALID_INTERNALUSER_BODY = """
        { "password": "TestPassword_123!", "backend_roles": ["backend"] }
        """;

    private static final String VALID_ROLESMAPPING_BODY = """
        { "backend_roles": ["some_backend_role"], "hosts": [], "users": [] }
        """;

    private static final String VALID_TENANT_BODY = """
        { "description": "test tenant" }
        """;

    /**
     * Poll {@code _tasks/{taskId}?wait_for_completion=true&timeout=30s} — a single call that blocks
     * until the task finishes. Returns the parsed response body.
     */
    private JsonNode awaitTaskCompletion(final TestRestClient client, final String taskId) throws Exception {
        final HttpResponse resp = client.get("_tasks/" + taskId + "?wait_for_completion=true&timeout=30s");
        assertThat("Task lookup failed: " + resp.getBody(), resp.getStatusCode(), is(200));
        return DefaultObjectMapper.readTree(resp.getBody());
    }

    private String extractTaskId(final HttpResponse resp) throws Exception {
        assertThat("Async submission failed: " + resp.getBody(), resp.getStatusCode(), is(200));
        final JsonNode json = DefaultObjectMapper.readTree(resp.getBody());
        assertThat("Async response missing 'task' field: " + resp.getBody(), json.has("task"), is(true));
        final String taskId = json.get("task").asText();
        assertThat("Task ID should be non-empty", taskId, notNullValue());
        assertThat("Task ID should be nodeId:taskId shape", taskId, containsString(":"));
        return taskId;
    }

    // ---------- sync / backwards-compatibility ----------

    @Test
    public void syncPutRole_defaultBehavior_unchanged() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final HttpResponse resp = client.putJson(apiPath("roles", "sync_role_default"), VALID_ROLE_BODY);
            // First-time create returns 201 CREATED as it always did
            assertThat(resp.getBody(), resp.getStatusCode(), is(201));
            assertThat(resp.getBody(), containsString("created"));
            // Idempotent second call becomes an update — 200 OK, "updated" message
            final HttpResponse update = client.putJson(apiPath("roles", "sync_role_default"), VALID_ROLE_BODY);
            assertThat(update.getBody(), update.getStatusCode(), is(200));
            assertThat(update.getBody(), containsString("updated"));
        }
    }

    @Test
    public void syncPutRole_explicitWaitForCompletionTrue_sameAsDefault() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final HttpResponse resp = client.putJson(apiPath("roles", "sync_role_explicit") + "?wait_for_completion=true", VALID_ROLE_BODY);
            assertThat(resp.getBody(), resp.getStatusCode(), is(201));
            assertThat(resp.getBody(), containsString("created"));
        }
    }

    @Test
    public void invalidBody_returnsSyncErrorEvenWhenAsyncRequested() throws Exception {
        // Validation happens before task submission, so bad requests still surface as 400 —
        // clients don't get a task ID for something that never runs.
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final HttpResponse resp = client.putJson(apiPath("roles", "invalid_role") + "?wait_for_completion=false", INVALID_ROLE_BODY);
            assertThat(resp.getBody(), resp.getStatusCode(), is(400));
            assertThat(resp.getBody(), not_(containsString("\"task\"")));
        }
    }

    // hamcrest 'not' would collide with a static import site above — inline wrapper
    private static org.hamcrest.Matcher<String> not_(org.hamcrest.Matcher<String> inner) {
        return org.hamcrest.CoreMatchers.not(inner);
    }

    // ---------- async: per-endpoint smoke ----------

    @Test
    public void asyncPutRole_returnsTaskIdAndPersists() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final HttpResponse submit = client.putJson(apiPath("roles", "async_role") + "?wait_for_completion=false", VALID_ROLE_BODY);
            final String taskId = extractTaskId(submit);
            final JsonNode taskJson = awaitTaskCompletion(client, taskId);
            assertThat("Task should complete: " + taskJson, taskJson.path("completed").asBoolean(), is(true));
            assertThat(
                "Stored task result should carry the success message",
                taskJson.at("/response/message").asText(),
                equalTo("'async_role' created.")
            );
            // Confirm the write actually applied and is readable via the sync GET path
            final HttpResponse readBack = client.get(apiPath("roles", "async_role"));
            assertThat(readBack.getBody(), readBack.getStatusCode(), is(200));
        }
    }

    @Test
    public void asyncPutInternalUser_returnsTaskIdAndPersists() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final HttpResponse submit = client.putJson(
                apiPath("internalusers", "async_user") + "?wait_for_completion=false",
                VALID_INTERNALUSER_BODY
            );
            final String taskId = extractTaskId(submit);
            final JsonNode taskJson = awaitTaskCompletion(client, taskId);
            assertThat("Task should complete: " + taskJson, taskJson.path("completed").asBoolean(), is(true));
            assertThat(taskJson.at("/response/message").asText(), equalTo("'async_user' created."));
        }
    }

    @Test
    public void asyncPutRolesMapping_returnsTaskId() throws Exception {
        // Prerequisite: create the role the mapping references; do it sync so the mapping write
        // has something to point at.
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            client.putJson(apiPath("roles", "mapping_target_role"), VALID_ROLE_BODY);
            final HttpResponse submit = client.putJson(
                apiPath("rolesmapping", "mapping_target_role") + "?wait_for_completion=false",
                VALID_ROLESMAPPING_BODY
            );
            final String taskId = extractTaskId(submit);
            final JsonNode taskJson = awaitTaskCompletion(client, taskId);
            assertThat("Task should complete: " + taskJson, taskJson.path("completed").asBoolean(), is(true));
        }
    }

    @Test
    public void asyncPutTenant_returnsTaskId() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final HttpResponse submit = client.putJson(
                apiPath("tenants", "async_tenant") + "?wait_for_completion=false",
                VALID_TENANT_BODY
            );
            final String taskId = extractTaskId(submit);
            final JsonNode taskJson = awaitTaskCompletion(client, taskId);
            assertThat("Task should complete: " + taskJson, taskJson.path("completed").asBoolean(), is(true));
        }
    }

    @Test
    public void asyncAuditEndpoint_acceptsWaitForCompletionParam() throws Exception {
        // Audit config has a bespoke body schema (full AuditConfig JSON), so we don't try to
        // successfully mutate it here — that's covered by the existing audit integration tests.
        // What we verify is that the shared plumbing accepts wait_for_completion=false on the
        // audit route (i.e. AuditApiAction's consumeParameters override doesn't leak the param
        // as unrecognized). A PUT with an intentionally minimal body returns a 4xx validation
        // error, NOT a 400 "unrecognized parameter" error.
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            final HttpResponse resp = client.putJson(apiPath("audit", "config") + "?wait_for_completion=false", "{}");
            assertThat(
                "wait_for_completion must not be treated as an unrecognized parameter: " + resp.getBody(),
                resp.getBody(),
                not_(containsString("unrecognized parameter"))
            );
        }
    }

    // ---------- cancellation: rejected ----------

    @Test
    public void submittedTask_isNotCancellable() throws Exception {
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER)) {
            // Submit and immediately try to cancel. TransportCancelTasksAction returns 200 OK at
            // the top level even for non-cancellable tasks; the actual rejection surfaces inside
            // `node_failures[*].caused_by` as an IllegalArgumentException whose reason contains
            // "doesn't support cancellation". If our task ever accidentally becomes cancellable
            // (e.g. by inheriting from CancellableTask), that error message disappears and this
            // assertion catches the regression.
            final HttpResponse submit = client.putJson(apiPath("roles", "noncancel_role") + "?wait_for_completion=false", VALID_ROLE_BODY);
            final String taskId = extractTaskId(submit);
            final HttpResponse cancel = client.post("_tasks/" + taskId + "/_cancel");
            assertThat(
                "Cancel body must indicate the task doesn't support cancellation: " + cancel.getBody(),
                cancel.getBody(),
                containsString("doesn't support cancellation")
            );
        }
    }
}
