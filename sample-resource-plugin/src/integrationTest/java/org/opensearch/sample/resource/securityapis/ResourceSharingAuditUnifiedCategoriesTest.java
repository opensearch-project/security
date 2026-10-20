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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_FULL_ACCESS;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SECURITY_SHARE_ENDPOINT;
import static org.opensearch.sample.utils.Constants.RESOURCE_GROUP_TYPE;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.sample.utils.Constants.WORKSPACE_TYPE;
import static org.opensearch.security.support.ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.security.support.ConfigConstants.OPENSEARCH_RESOURCE_SHARING_PROTECTED_TYPES;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Integration test verifying that an audit config using only the unified disabled_categories setting
 * (without the deprecated disabled_rest_categories / disabled_transport_categories) audits resource
 * sharing events. The legacy split defaults disable the RESOURCE_* categories and must not be applied
 * on top of disabled_categories.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ResourceSharingAuditUnifiedCategoriesTest {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
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
                List.of(RESOURCE_TYPE, RESOURCE_GROUP_TYPE, WORKSPACE_TYPE)
            )
        )
        .audit(
            new AuditConfiguration(true).filters(
                new AuditFilters().enabledRest(true)
                    .enabledTransport(true)
                    .disabledRestCategories(null)
                    .disabledTransportCategories(null)
                    .disabledCategories(List.of("AUTHENTICATED", "GRANTED_PRIVILEGES"))
            )
        )
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);

    @Test
    public void shouldNotApplyLegacySplitDefaultsWhenOnlyUnifiedCategoriesAreConfigured() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse response = client.get("_plugins/_security/api/audit");
            response.assertStatusCode(200);
            assertThat(
                response.getTextArrayFromJsonBody("/config/audit/disabled_categories"),
                containsInAnyOrder("AUTHENTICATED", "GRANTED_PRIVILEGES")
            );
            assertThat(response.getTextArrayFromJsonBody("/config/audit/disabled_rest_categories"), empty());
            assertThat(response.getTextArrayFromJsonBody("/config/audit/disabled_transport_categories"), empty());
        }
    }

    @Test
    public void shouldAuditResourceSharingEventsWhenOnlyUnifiedCategoriesAreConfigured() {
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

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.RESOURCE_SHARING_CHANGED);
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> msg.getCategory() == AuditCategory.RESOURCE_ACCESS_GRANTED);
    }
}
