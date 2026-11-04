/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.securityapis;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.awaitility.Awaitility;
import org.junit.Assert;
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
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_FULL_ACCESS;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SECURITY_SHARE_ENDPOINT;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.security.support.ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.security.support.ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Integration test verifying that disabling the RESOURCE_SHARING_CHANGED audit category at runtime
 * suppresses those events while leaving other categories intact.
 *
 * This test lives in its OWN class with its OWN dedicated cluster (rather than alongside the other
 * resource-sharing audit tests) because it mutates the cluster-wide audit configuration. Under a
 * shared {@code @ClassRule} cluster with randomized method ordering, a runtime config mutation could
 * leak into unrelated tests and cause flakiness. Isolating it keeps the blast radius to this class,
 * mirroring how {@code StandaloneAuditDynamicFilterSettingsTest} and friends are structured.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ResourceSharingAuditRuntimeConfigTest {

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

    @Test
    public void shouldRespectDisabledCategoriesAtRuntime() {
        // Disable RESOURCE_SHARING_CHANGED category at runtime, then perform a share.
        // The sharing should succeed but no RESOURCE_SHARING_CHANGED audit event should be produced.
        // RESOURCE_ACCESS_GRANTED should still fire (it's not disabled).
        //
        // This cluster uses security-index-based audit config (see .audit(...) above), so runtime
        // category changes go through the security audit API (PATCH _plugins/_security/api/audit),
        // NOT the standalone _cluster/settings keys (which are only wired when audit standalone mode
        // is enabled). The change propagates asynchronously via a security config reload, so we poll
        // the audit config until it reflects the disabled category before generating events.
        setDisabledTransportCategories("[\"RESOURCE_SHARING_CHANGED\"]");
        awaitDisabledTransportCategory("RESOURCE_SHARING_CHANGED", true);

        try {
            String resourceId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry(resourceId);

            try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    TestUtils.putSharingInfoPayload(
                        resourceId,
                        RESOURCE_TYPE,
                        SAMPLE_FULL_ACCESS,
                        Recipient.USERS,
                        FULL_ACCESS_USER.getName()
                    )
                );
            }

            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
            }

            // RESOURCE_SHARING_CHANGED should NOT appear (disabled)
            auditLogsRule.assertExactly(0, (AuditMessage msg) -> msg.getCategory() == AuditCategory.RESOURCE_SHARING_CHANGED);

            // RESOURCE_ACCESS_GRANTED should still appear (not disabled)
            auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.RESOURCE_ACCESS_GRANTED);
        } finally {
            // Reset the disabled categories. The dedicated cluster is torn down after this class, so
            // this is defensive hygiene rather than a correctness requirement for other tests.
            setDisabledTransportCategories("[]");
            awaitDisabledTransportCategory("RESOURCE_SHARING_CHANGED", false);
        }
    }

    /**
     * Updates the runtime audit filter's disabled_transport_categories via the security audit API.
     * Uses the admin certificate because updating audit config requires REST API admin access.
     */
    private void setDisabledTransportCategories(String jsonArray) {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.patch(
                "_plugins/_security/api/audit",
                "[{\"op\": \"replace\", \"path\": \"/config/audit/disabled_transport_categories\", \"value\": " + jsonArray + "}]"
            ).assertStatusCode(200);
        }
    }

    /**
     * Polls the audit config until disabled_transport_categories contains (or no longer contains) the
     * given category, since the security config reload that applies the change is asynchronous.
     */
    private void awaitDisabledTransportCategory(String category, boolean shouldBePresent) {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            Awaitility.await("Audit config disabled_transport_categories " + (shouldBePresent ? "contains " : "excludes ") + category)
                .pollInterval(Duration.ofMillis(250))
                .atMost(Duration.ofSeconds(10))
                .untilAsserted(() -> {
                    TestRestClient.HttpResponse response = client.get("_plugins/_security/api/audit");
                    response.assertStatusCode(200);
                    List<String> disabled = response.getTextArrayFromJsonBody("/config/audit/disabled_transport_categories");
                    if (shouldBePresent) {
                        Assert.assertTrue("expected " + category + " to be disabled, got " + disabled, disabled.contains(category));
                    } else {
                        Assert.assertFalse("expected " + category + " to be enabled, got " + disabled, disabled.contains(category));
                    }
                });
        }
    }
}
