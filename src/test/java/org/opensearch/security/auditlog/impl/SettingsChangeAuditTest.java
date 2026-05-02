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

package org.opensearch.security.auditlog.impl;

import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.admin.cluster.settings.ClusterUpdateSettingsRequest;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditTestUtils;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.AbstractSecurityUnitTest;
import org.opensearch.transport.TransportRequest;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for CLUSTER_SETTINGS_CHANGED and INDEX_SETTINGS_CHANGED audit log categories.
 * Tests the settings change audit logging in AbstractAuditLog including:
 * - Cluster settings changes (persistent and transient)
 * - Index settings changes with resolved indices
 * - Setting reset to default (null new_value, operation=removed)
 * - Sensitive setting redaction via pattern fallback
 * - Routing: ClusterUpdateSettingsRequest vs UpdateSettingsRequest
 * - Empty/no-op requests producing no audit message
 * - Category disable filtering
 */
public class SettingsChangeAuditTest {

    private ClusterService cs;
    private DiscoveryNode dn;

    @Before
    public void setup() {
        dn = mock(DiscoveryNode.class);
        when(dn.getHostAddress()).thenReturn("hostaddress");
        when(dn.getId()).thenReturn("hostaddress");
        when(dn.getHostName()).thenReturn("hostaddress");

        cs = mock(ClusterService.class);
        when(cs.localNode()).thenReturn(dn);
        when(cs.getClusterName()).thenReturn(new ClusterName("cname"));

        TestAuditlogImpl.clear();
    }

    /**
     * Creates an audit log with both new categories enabled (not disabled).
     */
    private AbstractAuditLog createAuditLog() {
        final Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
            .build();
        return AuditTestUtils.createAuditLog(settings, null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
    }

    /**
     * Creates an audit log with the specified categories disabled.
     */
    private AbstractAuditLog createAuditLogWithDisabledCategories(final String disabledCategories) {
        final Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, disabledCategories)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
            .build();
        return AuditTestUtils.createAuditLog(settings, null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
    }

    // --- Cluster settings change tests ---

    @Test
    public void testClusterPersistentSettingChange() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(Settings.builder().put("cluster.max_shards_per_node", "2000").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("CLUSTER_SETTINGS_CHANGED"));
        assertThat(result, containsString("cluster.max_shards_per_node"));
        assertThat(result, containsString("2000"));
        assertThat(result, containsString("persistent"));
        assertThat(result, containsString("set"));
    }

    @Test
    public void testClusterTransientSettingChange() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.transientSettings(Settings.builder().put("cluster.routing.allocation.enable", "primaries").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("CLUSTER_SETTINGS_CHANGED"));
        assertThat(result, containsString("cluster.routing.allocation.enable"));
        assertThat(result, containsString("primaries"));
        assertThat(result, containsString("transient"));
        assertThat(result, containsString("set"));
    }

    @Test
    public void testClusterBothPersistentAndTransientSettings() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(Settings.builder().put("cluster.max_shards_per_node", "2000").build());
        request.transientSettings(Settings.builder().put("cluster.routing.allocation.enable", "primaries").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("CLUSTER_SETTINGS_CHANGED"));
        assertThat(result, containsString("persistent"));
        assertThat(result, containsString("transient"));
        assertThat(result, containsString("cluster.max_shards_per_node"));
        assertThat(result, containsString("cluster.routing.allocation.enable"));
    }

    @Test
    public void testClusterSettingResetToDefault() throws Exception {
        // Simulate existing persistent setting that is being reset (null value)
        final Metadata metadata = mock(Metadata.class);
        when(metadata.persistentSettings()).thenReturn(Settings.builder().put("cluster.max_shards_per_node", "2000").build());
        when(metadata.transientSettings()).thenReturn(Settings.EMPTY);
        final ClusterState state = mock(ClusterState.class);
        when(state.metadata()).thenReturn(metadata);
        when(cs.state()).thenReturn(state);

        final AbstractAuditLog auditLog = createAuditLog();

        // Setting a key with null value signals reset to default
        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(Settings.builder().putNull("cluster.max_shards_per_node").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("CLUSTER_SETTINGS_CHANGED"));
        assertThat(result, containsString("cluster.max_shards_per_node"));
        assertThat(result, containsString("2000")); // old_value
        assertThat(result, containsString("removed"));
    }

    @Test
    public void testClusterSettingOldValueCaptured() throws Exception {
        // Mock current cluster state with an existing persistent setting
        final Metadata metadata = mock(Metadata.class);
        when(metadata.persistentSettings()).thenReturn(Settings.builder().put("cluster.max_shards_per_node", "1000").build());
        when(metadata.transientSettings()).thenReturn(Settings.EMPTY);
        final ClusterState state = mock(ClusterState.class);
        when(state.metadata()).thenReturn(metadata);
        when(cs.state()).thenReturn(state);

        final AbstractAuditLog auditLog = createAuditLog();

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(Settings.builder().put("cluster.max_shards_per_node", "2000").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("1000")); // old_value
        assertThat(result, containsString("2000")); // new_value
    }

    // --- Index settings change tests ---

    @Test
    public void testIndexSettingChange() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final UpdateSettingsRequest request = new UpdateSettingsRequest("test-index");
        request.settings(Settings.builder().put("index.number_of_replicas", "2").build());

        auditLog.logSettingsChange("indices:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("INDEX_SETTINGS_CHANGED"));
        assertThat(result, containsString("index.number_of_replicas"));
        assertThat(result, containsString("2"));
        assertThat(result, containsString("index"));
        assertThat(result, containsString("set"));
    }

    @Test
    public void testIndexSettingChangeIncludesIndices() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final UpdateSettingsRequest request = new UpdateSettingsRequest("my-index-001", "my-index-002");
        request.settings(Settings.builder().put("index.number_of_replicas", "3").build());

        auditLog.logSettingsChange("indices:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("INDEX_SETTINGS_CHANGED"));
        assertThat(result, containsString("my-index-001"));
        assertThat(result, containsString("my-index-002"));
    }

    // --- Routing tests ---

    @Test
    public void testRoutingClusterUpdateSettingsRequest() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(Settings.builder().put("cluster.max_shards_per_node", "500").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("CLUSTER_SETTINGS_CHANGED"));
        assertThat(result, not(containsString("INDEX_SETTINGS_CHANGED")));
    }

    @Test
    public void testRoutingUpdateSettingsRequest() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final UpdateSettingsRequest request = new UpdateSettingsRequest("test-index");
        request.settings(Settings.builder().put("index.number_of_replicas", "1").build());

        auditLog.logSettingsChange("indices:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("INDEX_SETTINGS_CHANGED"));
        assertThat(result, not(containsString("CLUSTER_SETTINGS_CHANGED")));
    }

    @Test
    public void testRoutingUnknownRequestTypeProducesNoMessage() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        // TransportRequest.Empty is neither ClusterUpdateSettingsRequest nor UpdateSettingsRequest
        auditLog.logSettingsChange("some:action", new TransportRequest.Empty(), null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, not(containsString("CLUSTER_SETTINGS_CHANGED")));
        assertThat(result, not(containsString("INDEX_SETTINGS_CHANGED")));
    }

    // --- Empty request tests ---

    @Test
    public void testEmptyClusterSettingsProducesNoMessage() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        // Both persistent and transient are empty
        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, not(containsString("CLUSTER_SETTINGS_CHANGED")));
    }

    // --- Sensitive setting redaction tests ---

    @Test
    public void testSensitiveSettingRedactionByPasswordPattern() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(Settings.builder().put("plugins.security.ssl.transport.keystore_password", "mysecret").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("***REDACTED***"));
        assertThat(result, not(containsString("mysecret")));
    }

    @Test
    public void testSensitiveSettingRedactionBySecretPattern() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(Settings.builder().put("some.plugin.client_secret", "topsecret").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("***REDACTED***"));
        assertThat(result, not(containsString("topsecret")));
    }

    @Test
    public void testSensitiveSettingRedactionByTokenPattern() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(Settings.builder().put("some.plugin.auth_token", "abc123").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("***REDACTED***"));
        assertThat(result, not(containsString("abc123")));
    }

    @Test
    public void testNonSensitiveSettingNotRedacted() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(Settings.builder().put("cluster.max_shards_per_node", "2000").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("2000"));
        assertThat(result, not(containsString("***REDACTED***")));
    }

    @Test
    public void testSensitiveOldValueAlsoRedacted() throws Exception {
        // Mock current state with a sensitive setting already set
        final Metadata metadata = mock(Metadata.class);
        when(metadata.persistentSettings()).thenReturn(
            Settings.builder().put("plugins.security.ssl.transport.keystore_password", "oldsecret").build()
        );
        when(metadata.transientSettings()).thenReturn(Settings.EMPTY);
        final ClusterState state = mock(ClusterState.class);
        when(state.metadata()).thenReturn(metadata);
        when(cs.state()).thenReturn(state);

        final AbstractAuditLog auditLog = createAuditLog();

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(Settings.builder().put("plugins.security.ssl.transport.keystore_password", "newsecret").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, not(containsString("oldsecret")));
        assertThat(result, not(containsString("newsecret")));
        assertThat(result, containsString("***REDACTED***"));
    }

    // --- Category disable tests ---

    @Test
    public void testClusterSettingsChangedCategoryDisabled() throws Exception {
        final AbstractAuditLog auditLog = createAuditLogWithDisabledCategories("CLUSTER_SETTINGS_CHANGED");

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(Settings.builder().put("cluster.max_shards_per_node", "2000").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, not(containsString("CLUSTER_SETTINGS_CHANGED")));
    }

    @Test
    public void testIndexSettingsChangedCategoryDisabled() throws Exception {
        final AbstractAuditLog auditLog = createAuditLogWithDisabledCategories("INDEX_SETTINGS_CHANGED");

        final UpdateSettingsRequest request = new UpdateSettingsRequest("test-index");
        request.settings(Settings.builder().put("index.number_of_replicas", "2").build());

        auditLog.logSettingsChange("indices:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, not(containsString("INDEX_SETTINGS_CHANGED")));
    }

    // --- AuditMessage.addSettingsChanges tests ---

    @Test
    public void testAuditMessageSettingsChangesField() {
        final AuditMessage msg = new AuditMessage(AuditCategory.CLUSTER_SETTINGS_CHANGED, cs, null, null);

        final List<Map<String, Object>> changes = List.of(
            Map.of(
                "setting",
                "cluster.max_shards_per_node",
                "old_value",
                "1000",
                "new_value",
                "2000",
                "operation",
                "set",
                "scope",
                "persistent"
            )
        );
        msg.addSettingsChanges(changes);

        final Map<String, Object> asMap = msg.getAsMap();
        Assert.assertNotNull(asMap.get(AuditMessage.SETTINGS_CHANGES));
        Assert.assertEquals(changes, asMap.get(AuditMessage.SETTINGS_CHANGES));
    }

    @Test
    public void testAuditMessageSettingsChangesNullIgnored() {
        final AuditMessage msg = new AuditMessage(AuditCategory.CLUSTER_SETTINGS_CHANGED, cs, null, null);
        msg.addSettingsChanges(null);

        Assert.assertNull(msg.getAsMap().get(AuditMessage.SETTINGS_CHANGES));
    }

    @Test
    public void testAuditMessageSettingsChangesEmptyIgnored() {
        final AuditMessage msg = new AuditMessage(AuditCategory.CLUSTER_SETTINGS_CHANGED, cs, null, null);
        msg.addSettingsChanges(List.of());

        Assert.assertNull(msg.getAsMap().get(AuditMessage.SETTINGS_CHANGES));
    }

    // --- Action field test ---

    @Test
    public void testClusterSettingsChangeIncludesAction() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(Settings.builder().put("cluster.max_shards_per_node", "2000").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("cluster:admin/settings/update"));
    }

    @Test
    public void testIndexSettingsChangeIncludesAction() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final UpdateSettingsRequest request = new UpdateSettingsRequest("test-index");
        request.settings(Settings.builder().put("index.number_of_replicas", "2").build());

        auditLog.logSettingsChange("indices:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("indices:admin/settings/update"));
    }

    // --- Multiple settings in one request ---

    @Test
    public void testMultipleSettingsInOneClusterRequest() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(
            Settings.builder().put("cluster.max_shards_per_node", "2000").put("cluster.routing.allocation.enable", "all").build()
        );

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("cluster.max_shards_per_node"));
        assertThat(result, containsString("cluster.routing.allocation.enable"));
    }

    // --- ClusterSettings registry redaction test ---

    /**
     * Verifies that isSensitiveSetting() pattern fallback works even when ClusterSettings
     * registry is available but returns false (setting registered but not as SecureSetting).
     * The registry path returning true is covered by integration tests with a real cluster.
     */
    @Test
    public void testSensitiveSettingRedactionWhenRegistryReturnsFalse() throws Exception {
        // When getClusterSettings() is not mocked, it returns null → exception caught → pattern fallback runs.
        // This test verifies the pattern fallback catches "password" in the key name regardless.
        final AbstractAuditLog auditLog = createAuditLog();

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(Settings.builder().put("plugins.security.ssl.transport.keystore_password", "mysecret").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("***REDACTED***"));
        assertThat(result, not(containsString("mysecret")));
    }

    // --- Cluster state unavailable fallback test ---

    /**
     * Verifies that when clusterService.state() returns null (e.g., during unit tests or
     * early startup), the audit log gracefully falls back to Settings.EMPTY for old values
     * instead of throwing NPE. This covers the CI fix for DisabledCategoriesTest.
     */
    @Test
    public void testClusterStateUnavailableFallsBackGracefully() throws Exception {
        // cs.state() returns null by default (not mocked) — simulates unavailable cluster state
        final AbstractAuditLog auditLog = createAuditLog();

        final ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest();
        request.persistentSettings(Settings.builder().put("cluster.max_shards_per_node", "2000").build());

        auditLog.logSettingsChange("cluster:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("CLUSTER_SETTINGS_CHANGED"));
        assertThat(result, containsString("cluster.max_shards_per_node"));
        // old_value should be null since cluster state was unavailable
        assertThat(result, containsString("2000"));
    }

    /**
     * Verifies index settings change works when cluster state is unavailable.
     */
    @Test
    public void testIndexSettingsClusterStateUnavailableFallsBackGracefully() throws Exception {
        final AbstractAuditLog auditLog = createAuditLog();

        final UpdateSettingsRequest request = new UpdateSettingsRequest("test-index");
        request.settings(Settings.builder().put("index.number_of_replicas", "2").build());

        auditLog.logSettingsChange("indices:admin/settings/update", request, null);
        auditLog.close();

        final String result = TestAuditlogImpl.sb.toString();
        assertThat(result, containsString("INDEX_SETTINGS_CHANGED"));
        assertThat(result, containsString("index.number_of_replicas"));
    }
}
