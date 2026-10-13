/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auditlog.impl;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditTestUtils;
import org.opensearch.security.auditlog.NullAuditLog;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.AbstractSecurityUnitTest;
import org.opensearch.transport.TransportRequest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for resource sharing audit logging methods in AbstractAuditLog.
 * Tests logResourceAccessGranted, logResourceAccessDenied, and logResourceSharingChanged.
 */
public class ResourceSharingAuditLogTest {

    private ClusterService cs = mock(ClusterService.class);
    private DiscoveryNode dn = mock(DiscoveryNode.class);

    @Before
    public void setup() {
        when(dn.getHostAddress()).thenReturn("hostaddress");
        when(dn.getId()).thenReturn("hostaddress");
        when(dn.getHostName()).thenReturn("hostaddress");
        when(cs.localNode()).thenReturn(dn);
        when(cs.getClusterName()).thenReturn(new ClusterName("cname"));
    }

    private AbstractAuditLog createAuditLogWithAllCategoriesEnabled() {
        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .build();
        return AuditTestUtils.createAuditLog(settings, null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
    }

    // --- logResourceAccessGranted tests ---

    @Test
    public void testLogResourceAccessGrantedProducesMessage() {
        AbstractAuditLog al = createAuditLogWithAllCategoriesEnabled();
        TestAuditlogImpl.clear();

        al.logResourceAccessGranted(
            "indices:data/read/get",
            "resource-123",
            "saved_query",
            ".sample_resources",
            mock(TransportRequest.class),
            null
        );

        assertThat(TestAuditlogImpl.messages.size(), is(1));
        assertThat(TestAuditlogImpl.messages.get(0).getCategory(), is(AuditCategory.RESOURCE_ACCESS_GRANTED));
    }

    @Test
    public void testLogResourceAccessGrantedContainsResourceFields() {
        AbstractAuditLog al = createAuditLogWithAllCategoriesEnabled();
        TestAuditlogImpl.clear();

        al.logResourceAccessGranted(
            "indices:data/read/get",
            "resource-123",
            "saved_query",
            ".sample_resources",
            mock(TransportRequest.class),
            null
        );

        AuditMessage msg = TestAuditlogImpl.messages.get(0);
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_ID), equalTo("resource-123"));
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_TYPE), equalTo("saved_query"));
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_INDEX), equalTo(".sample_resources"));
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_ACCESS_RESULT), equalTo("granted"));
    }

    @Test
    public void testLogResourceAccessGrantedContainsAction() {
        AbstractAuditLog al = createAuditLogWithAllCategoriesEnabled();
        TestAuditlogImpl.clear();

        al.logResourceAccessGranted(
            "indices:data/read/get",
            "resource-123",
            "saved_query",
            ".sample_resources",
            mock(TransportRequest.class),
            null
        );

        AuditMessage msg = TestAuditlogImpl.messages.get(0);
        assertThat(msg.getAsMap().get(AuditMessage.TRANSPORT_ACTION), equalTo("indices:data/read/get"));
    }

    @Test
    public void testLogResourceAccessGrantedIsFilteredWhenCategoryDisabled() {
        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "RESOURCE_ACCESS_GRANTED")
            .build();
        AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
        TestAuditlogImpl.clear();

        al.logResourceAccessGranted(
            "indices:data/read/get",
            "resource-123",
            "saved_query",
            ".sample_resources",
            mock(TransportRequest.class),
            null
        );

        assertThat(TestAuditlogImpl.messages.size(), is(0));
    }

    // --- logResourceAccessDenied tests ---

    @Test
    public void testLogResourceAccessDeniedProducesMessage() {
        AbstractAuditLog al = createAuditLogWithAllCategoriesEnabled();
        TestAuditlogImpl.clear();

        al.logResourceAccessDenied("indices:data/read/get", "resource-456", "dashboard", ".dashboards", mock(TransportRequest.class), null);

        assertThat(TestAuditlogImpl.messages.size(), is(1));
        assertThat(TestAuditlogImpl.messages.get(0).getCategory(), is(AuditCategory.RESOURCE_ACCESS_DENIED));
    }

    @Test
    public void testLogResourceAccessDeniedContainsResourceFields() {
        AbstractAuditLog al = createAuditLogWithAllCategoriesEnabled();
        TestAuditlogImpl.clear();

        al.logResourceAccessDenied("indices:data/read/get", "resource-456", "dashboard", ".dashboards", mock(TransportRequest.class), null);

        AuditMessage msg = TestAuditlogImpl.messages.get(0);
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_ID), equalTo("resource-456"));
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_TYPE), equalTo("dashboard"));
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_INDEX), equalTo(".dashboards"));
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_ACCESS_RESULT), equalTo("denied"));
    }

    @Test
    public void testLogResourceAccessDeniedIsFilteredWhenCategoryDisabled() {
        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "RESOURCE_ACCESS_DENIED")
            .build();
        AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
        TestAuditlogImpl.clear();

        al.logResourceAccessDenied("indices:data/read/get", "resource-456", "dashboard", ".dashboards", mock(TransportRequest.class), null);

        assertThat(TestAuditlogImpl.messages.size(), is(0));
    }

    // --- logResourceSharingChanged tests ---

    @Test
    public void testLogResourceSharingChangedProducesMessageOnSuccess() {
        AbstractAuditLog al = createAuditLogWithAllCategoriesEnabled();
        TestAuditlogImpl.clear();

        al.logResourceSharingChanged(
            "resource-789",
            "saved_query",
            "share",
            "success",
            null,
            null,
            "{users: [bob]}",
            mock(TransportRequest.class),
            null
        );

        assertThat(TestAuditlogImpl.messages.size(), is(1));
        assertThat(TestAuditlogImpl.messages.get(0).getCategory(), is(AuditCategory.RESOURCE_SHARING_CHANGED));
    }

    @Test
    public void testLogResourceSharingChangedProducesMessageOnFailure() {
        AbstractAuditLog al = createAuditLogWithAllCategoriesEnabled();
        TestAuditlogImpl.clear();

        al.logResourceSharingChanged(
            "resource-789",
            "saved_query",
            "share",
            "failed",
            null,
            null,
            "{users: [bob]}",
            mock(TransportRequest.class),
            null
        );

        assertThat(TestAuditlogImpl.messages.size(), is(1));
        AuditMessage msg = TestAuditlogImpl.messages.get(0);
        assertThat(msg.getCategory(), is(AuditCategory.RESOURCE_SHARING_CHANGED));
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_SHARING_RESULT), equalTo("failed"));
    }

    @Test
    public void testLogResourceSharingChangedContainsAllFieldsForPatch() {
        AbstractAuditLog al = createAuditLogWithAllCategoriesEnabled();
        TestAuditlogImpl.clear();

        al.logResourceSharingChanged(
            "resource-789",
            "saved_query",
            "patch",
            "success",
            "{users: [alice]}",
            "{users: [bob]}",
            null,
            mock(TransportRequest.class),
            null
        );

        AuditMessage msg = TestAuditlogImpl.messages.get(0);
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_ID), equalTo("resource-789"));
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_TYPE), equalTo("saved_query"));
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_SHARING_ACTION), equalTo("patch"));
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_SHARING_RESULT), equalTo("success"));
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_RECIPIENTS_ADDED), equalTo("{users: [alice]}"));
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_RECIPIENTS_REVOKED), equalTo("{users: [bob]}"));
    }

    @Test
    public void testLogResourceSharingChangedContainsShareWithForPut() {
        AbstractAuditLog al = createAuditLogWithAllCategoriesEnabled();
        TestAuditlogImpl.clear();

        al.logResourceSharingChanged(
            "resource-789",
            "saved_query",
            "share",
            "success",
            null,
            null,
            "{users: [bob]}",
            mock(TransportRequest.class),
            null
        );

        AuditMessage msg = TestAuditlogImpl.messages.get(0);
        assertThat(msg.getAsMap().get(AuditMessage.RESOURCE_SHARE_WITH), equalTo("{users: [bob]}"));
    }

    @Test
    public void testLogResourceSharingChangedIsFilteredWhenCategoryDisabled() {
        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "RESOURCE_SHARING_CHANGED")
            .build();
        AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
        TestAuditlogImpl.clear();

        al.logResourceSharingChanged(
            "resource-789",
            "saved_query",
            "share",
            "success",
            null,
            null,
            "{users: [bob]}",
            mock(TransportRequest.class),
            null
        );

        assertThat(TestAuditlogImpl.messages.size(), is(0));
    }

    @Test
    public void testLogResourceSharingChangedNullRecipientsAreOmittedFromMessage() {
        AbstractAuditLog al = createAuditLogWithAllCategoriesEnabled();
        TestAuditlogImpl.clear();

        // PUT share: only shareWith is set, add/revoke are null
        al.logResourceSharingChanged(
            "resource-789",
            "saved_query",
            "share",
            "success",
            null,
            null,
            "{users: [bob]}",
            mock(TransportRequest.class),
            null
        );

        AuditMessage msg = TestAuditlogImpl.messages.get(0);
        assertThat(msg.getAsMap().containsKey(AuditMessage.RESOURCE_RECIPIENTS_ADDED), is(false));
        assertThat(msg.getAsMap().containsKey(AuditMessage.RESOURCE_RECIPIENTS_REVOKED), is(false));
    }

    // --- NullAuditLog tests (auditing disabled) ---

    @Test
    public void testNullAuditLogResourceAccessGrantedIsNoOp() {
        NullAuditLog nullLog = new NullAuditLog();
        // Should not throw — no-op implementation
        nullLog.logResourceAccessGranted(
            "indices:data/read/get",
            "resource-123",
            "saved_query",
            ".sample_resources",
            mock(TransportRequest.class),
            null
        );
    }

    @Test
    public void testNullAuditLogResourceAccessDeniedIsNoOp() {
        NullAuditLog nullLog = new NullAuditLog();
        nullLog.logResourceAccessDenied(
            "indices:data/read/get",
            "resource-456",
            "dashboard",
            ".dashboards",
            mock(TransportRequest.class),
            null
        );
    }

    @Test
    public void testNullAuditLogResourceSharingChangedIsNoOp() {
        NullAuditLog nullLog = new NullAuditLog();
        nullLog.logResourceSharingChanged(
            "resource-789",
            "saved_query",
            "share",
            "success",
            null,
            null,
            "{users: [bob]}",
            mock(TransportRequest.class),
            null
        );
    }
}
