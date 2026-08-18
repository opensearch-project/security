/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.securityapis;

import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.Version;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.sample.resource.TestUtils;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.resources.sharing.Recipient;
import org.opensearch.security.resources.sharing.Recipients;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_FULL_ACCESS;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SECURITY_SHARE_ENDPOINT;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.security.support.ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.security.support.ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Integration tests verifying that resource sharing audit events are produced
 * with correct categories and fields when resource access decisions and
 * sharing mutations occur.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ResourceSharingAuditTest {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS_COORDINATOR)
        .plugin(
            new PluginInfo(
                SampleResourcePlugin.class.getName(),
                "classpath plugin",
                "NA",
                Version.CURRENT,
                "21",
                SampleResourcePlugin.class.getName(),
                null,
                List.of(OpenSearchSecurityPlugin.class.getName()),
                false
            )
        )
        .anonymousAuth(true)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN, FULL_ACCESS_USER, TestUtils.LIMITED_ACCESS_USER, NO_ACCESS_USER)
        .nodeSettings(
            Map.of(
                OPENSEARCH_RESOURCE_SHARING_ENABLED,
                true,
                SECURITY_SYSTEM_INDICES_ENABLED_KEY,
                true,
                OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES,
                List.of(RESOURCE_TYPE)
            )
        )
        .audit(
            new AuditConfiguration(true).filters(
                new AuditFilters().enabledRest(true)
                    .enabledTransport(true)
                    .disabledRestCategories(List.of())
                    .disabledTransportCategories(List.of())
            )
        )
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);

    @After
    public void clearIndices() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(RESOURCE_INDEX_NAME);
            client.delete(RESOURCE_SHARING_INDEX);
        }
    }

    @Test
    public void shouldProduceResourceSharingChangedOnPutShare() {
        // Admin creates a resource, then shares it
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.putJson(
                SECURITY_SHARE_ENDPOINT,
                TestUtils.putSharingInfoPayload(resourceId, RESOURCE_TYPE, SAMPLE_FULL_ACCESS, Recipient.USERS, FULL_ACCESS_USER.getName())
            );
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.RESOURCE_SHARING_CHANGED) return false;
            Map<String, Object> fields = msg.getAsMap();
            return resourceId.equals(fields.get(AuditMessage.RESOURCE_ID))
                && RESOURCE_TYPE.equals(fields.get(AuditMessage.RESOURCE_TYPE))
                && "share".equals(fields.get(AuditMessage.RESOURCE_SHARING_ACTION));
        });
    }

    @Test
    public void shouldProduceResourceAccessGrantedWhenSharedUserAccesses() {
        // Admin creates resource, shares with FULL_ACCESS_USER
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.putJson(
                SECURITY_SHARE_ENDPOINT,
                TestUtils.putSharingInfoPayload(resourceId, RESOURCE_TYPE, SAMPLE_FULL_ACCESS, Recipient.USERS, FULL_ACCESS_USER.getName())
            );
        }

        // FULL_ACCESS_USER accesses the shared resource
        try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
            client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.RESOURCE_ACCESS_GRANTED) return false;
            Map<String, Object> fields = msg.getAsMap();
            return resourceId.equals(fields.get(AuditMessage.RESOURCE_ID))
                && "granted".equals(fields.get(AuditMessage.RESOURCE_ACCESS_RESULT));
        });
    }

    @Test
    public void shouldProduceResourceAccessDeniedWhenUnsharedUserAccesses() {
        // Admin creates resource, does NOT share with NO_ACCESS_USER
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);

        // NO_ACCESS_USER tries to access — should be denied
        try (TestRestClient client = cluster.getRestClient(NO_ACCESS_USER)) {
            client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.RESOURCE_ACCESS_DENIED) return false;
            Map<String, Object> fields = msg.getAsMap();
            return resourceId.equals(fields.get(AuditMessage.RESOURCE_ID))
                && "denied".equals(fields.get(AuditMessage.RESOURCE_ACCESS_RESULT));
        });
    }

    @Test
    public void shouldStillProduceGrantedPrivilegesAlongsideResourceAccess() {
        // Verify additive behavior — GRANTED_PRIVILEGES still fires for resource access
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.putJson(
                SECURITY_SHARE_ENDPOINT,
                TestUtils.putSharingInfoPayload(resourceId, RESOURCE_TYPE, SAMPLE_FULL_ACCESS, Recipient.USERS, FULL_ACCESS_USER.getName())
            );
        }

        // FULL_ACCESS_USER accesses the resource
        try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
            client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
        }

        // Both GRANTED_PRIVILEGES and RESOURCE_ACCESS_GRANTED should fire
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.GRANTED_PRIVILEGES);
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.RESOURCE_ACCESS_GRANTED);
    }

    @Test
    public void shouldIncludeResourceFieldsInSharingChangedEvent() {
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.putJson(
                SECURITY_SHARE_ENDPOINT,
                TestUtils.putSharingInfoPayload(resourceId, RESOURCE_TYPE, SAMPLE_FULL_ACCESS, Recipient.USERS, FULL_ACCESS_USER.getName())
            );
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.RESOURCE_SHARING_CHANGED) return false;
            Map<String, Object> fields = msg.getAsMap();
            // Verify all expected fields are present
            return fields.get(AuditMessage.RESOURCE_ID) != null
                && fields.get(AuditMessage.RESOURCE_TYPE) != null
                && fields.get(AuditMessage.RESOURCE_SHARING_ACTION) != null
                && fields.get(AuditMessage.RESOURCE_SHARE_WITH) != null
                && fields.get(AuditMessage.REQUEST_EFFECTIVE_USER) != null;
        });
    }

    @Test
    public void shouldNotProduceResourceSharingChangedOnGetSharingInfo() {
        // GET is read-only — should NOT produce RESOURCE_SHARING_CHANGED
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.get(SECURITY_SHARE_ENDPOINT + "?resource_id=" + resourceId + "&resource_type=" + RESOURCE_TYPE);
        }

        auditLogsRule.assertExactly(0, (AuditMessage msg) -> msg.getCategory() == AuditCategory.RESOURCE_SHARING_CHANGED);
    }

    @Test
    public void shouldProduceResourceSharingChangedOnPatchAdd() {
        // PATCH with "add" should produce RESOURCE_SHARING_CHANGED with action "patch"
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);

        Map<Recipient, java.util.Set<String>> recs = new java.util.HashMap<>();
        recs.put(Recipient.USERS, java.util.Set.of(FULL_ACCESS_USER.getName()));
        Recipients recipients = new Recipients(recs);

        TestUtils.PatchSharingInfoPayloadBuilder patchBuilder = new TestUtils.PatchSharingInfoPayloadBuilder();
        patchBuilder.resourceId(resourceId).resourceType(RESOURCE_TYPE).share(recipients, SAMPLE_FULL_ACCESS);

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.patch(SECURITY_SHARE_ENDPOINT, patchBuilder.build());
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.RESOURCE_SHARING_CHANGED) return false;
            Map<String, Object> fields = msg.getAsMap();
            return resourceId.equals(fields.get(AuditMessage.RESOURCE_ID))
                && "patch".equals(fields.get(AuditMessage.RESOURCE_SHARING_ACTION));
        });
    }

    @Test
    public void shouldProduceResourceSharingChangedOnPatchRevoke() {
        // First share, then revoke via PATCH — should produce RESOURCE_SHARING_CHANGED
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);

        // Share first
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.putJson(
                SECURITY_SHARE_ENDPOINT,
                TestUtils.putSharingInfoPayload(resourceId, RESOURCE_TYPE, SAMPLE_FULL_ACCESS, Recipient.USERS, FULL_ACCESS_USER.getName())
            );
        }

        // Now revoke via PATCH
        Map<Recipient, java.util.Set<String>> recs = new java.util.HashMap<>();
        recs.put(Recipient.USERS, java.util.Set.of(FULL_ACCESS_USER.getName()));
        Recipients recipients = new Recipients(recs);

        TestUtils.PatchSharingInfoPayloadBuilder patchBuilder = new TestUtils.PatchSharingInfoPayloadBuilder();
        patchBuilder.resourceId(resourceId).resourceType(RESOURCE_TYPE).revoke(recipients, SAMPLE_FULL_ACCESS);

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.patch(SECURITY_SHARE_ENDPOINT, patchBuilder.build());
        }

        // Should have at least 2 RESOURCE_SHARING_CHANGED events (one share, one revoke)
        auditLogsRule.assertAtLeast(2, (AuditMessage msg) -> msg.getCategory() == AuditCategory.RESOURCE_SHARING_CHANGED);
    }

    @Test
    public void shouldAuditDeniedSharingWhenMutationFails() {
        // Attempt to share a non-existent resource — SecurityFilter denies at the resource access level
        // before reaching ShareTransportAction, producing a RESOURCE_ACCESS_DENIED event
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.putJson(
                SECURITY_SHARE_ENDPOINT,
                TestUtils.putSharingInfoPayload(
                    "non-existent-id",
                    RESOURCE_TYPE,
                    SAMPLE_FULL_ACCESS,
                    Recipient.USERS,
                    FULL_ACCESS_USER.getName()
                )
            );
        }

        // The share request goes through SecurityFilter's resource evaluator and gets denied
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.RESOURCE_ACCESS_DENIED) return false;
            Map<String, Object> fields = msg.getAsMap();
            return "non-existent-id".equals(fields.get(AuditMessage.RESOURCE_ID));
        });
    }

    @Test
    public void shouldIncludeEffectiveUserInAccessGrantedEvent() {
        // Verify the user field is correctly populated in access events
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.putJson(
                SECURITY_SHARE_ENDPOINT,
                TestUtils.putSharingInfoPayload(resourceId, RESOURCE_TYPE, SAMPLE_FULL_ACCESS, Recipient.USERS, FULL_ACCESS_USER.getName())
            );
        }

        try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
            client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.RESOURCE_ACCESS_GRANTED) return false;
            Map<String, Object> fields = msg.getAsMap();
            return FULL_ACCESS_USER.getName().equals(fields.get(AuditMessage.REQUEST_EFFECTIVE_USER))
                && resourceId.equals(fields.get(AuditMessage.RESOURCE_ID));
        });
    }

    @Test
    public void shouldIncludeEffectiveUserInAccessDeniedEvent() {
        // Verify the user field is correctly populated in denied events
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);

        try (TestRestClient client = cluster.getRestClient(NO_ACCESS_USER)) {
            client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.RESOURCE_ACCESS_DENIED) return false;
            Map<String, Object> fields = msg.getAsMap();
            return NO_ACCESS_USER.getName().equals(fields.get(AuditMessage.REQUEST_EFFECTIVE_USER))
                && resourceId.equals(fields.get(AuditMessage.RESOURCE_ID));
        });
    }

    @Test
    public void shouldProduceAccessDeniedAfterRevoke() {
        // Full lifecycle: share → access granted → revoke → access denied
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);

        // Share with FULL_ACCESS_USER
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.putJson(
                SECURITY_SHARE_ENDPOINT,
                TestUtils.putSharingInfoPayload(resourceId, RESOURCE_TYPE, SAMPLE_FULL_ACCESS, Recipient.USERS, FULL_ACCESS_USER.getName())
            );
        }

        // Access succeeds
        try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
            TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            response.assertStatusCode(200);
        }

        // Revoke via PATCH
        Map<Recipient, java.util.Set<String>> recs = new java.util.HashMap<>();
        recs.put(Recipient.USERS, java.util.Set.of(FULL_ACCESS_USER.getName()));
        Recipients recipients = new Recipients(recs);

        TestUtils.PatchSharingInfoPayloadBuilder patchBuilder = new TestUtils.PatchSharingInfoPayloadBuilder();
        patchBuilder.resourceId(resourceId).resourceType(RESOURCE_TYPE).revoke(recipients, SAMPLE_FULL_ACCESS);

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.patch(SECURITY_SHARE_ENDPOINT, patchBuilder.build());
        }

        // Access now denied
        try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
            client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
        }

        // Should have both GRANTED and DENIED events for the same resource
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.RESOURCE_ACCESS_GRANTED) return false;
            return resourceId.equals(msg.getAsMap().get(AuditMessage.RESOURCE_ID));
        });
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.RESOURCE_ACCESS_DENIED) return false;
            return resourceId.equals(msg.getAsMap().get(AuditMessage.RESOURCE_ID));
        });
    }

    @Test
    public void shouldIncludeResourceTypeInAllEvents() {
        // Verify resource_type field is consistent across access and sharing events
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.putJson(
                SECURITY_SHARE_ENDPOINT,
                TestUtils.putSharingInfoPayload(resourceId, RESOURCE_TYPE, SAMPLE_FULL_ACCESS, Recipient.USERS, FULL_ACCESS_USER.getName())
            );
        }

        try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
            client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
        }

        // Both sharing changed and access granted should have the same resource_type
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.RESOURCE_SHARING_CHANGED) return false;
            return RESOURCE_TYPE.equals(msg.getAsMap().get(AuditMessage.RESOURCE_TYPE));
        });
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.RESOURCE_ACCESS_GRANTED) return false;
            return RESOURCE_TYPE.equals(msg.getAsMap().get(AuditMessage.RESOURCE_TYPE));
        });
    }

    @Test
    public void shouldProduceResourceAccessGrantedForOwner() {
        // Owner accessing their own resource — should still produce RESOURCE_ACCESS_GRANTED
        // (owner access goes through ResourceAccessEvaluator which auto-grants owners)
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);

        // Admin (owner) accesses their own resource
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.RESOURCE_ACCESS_GRANTED) return false;
            Map<String, Object> fields = msg.getAsMap();
            return resourceId.equals(fields.get(AuditMessage.RESOURCE_ID))
                && USER_ADMIN.getName().equals(fields.get(AuditMessage.REQUEST_EFFECTIVE_USER));
        });
    }

    @Test
    public void shouldNotProduceResourceAccessEventsForAdminCert() {
        // Admin cert users bypass SecurityFilter's resource evaluator entirely
        // (they hit the early return: if (userIsAdmin || confRequest || ...) chain.proceed)
        // So NO resource access events should fire for admin cert requests
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
        }

        auditLogsRule.assertExactly(0, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.RESOURCE_ACCESS_GRANTED && msg.getCategory() != AuditCategory.RESOURCE_ACCESS_DENIED)
                return false;
            return resourceId.equals(msg.getAsMap().get(AuditMessage.RESOURCE_ID));
        });
    }

}
