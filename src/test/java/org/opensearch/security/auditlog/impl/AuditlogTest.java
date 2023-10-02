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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditTestUtils;
import org.opensearch.security.auditlog.helper.RetrySink;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl;
import org.opensearch.security.filter.SecurityRequestChannel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.AbstractSecurityUnitTest;
import org.opensearch.transport.TransportRequest;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuditlogTest {

    ClusterService cs = mock(ClusterService.class);
    DiscoveryNode dn = mock(DiscoveryNode.class);

    @Before
    public void setup() {
        when(dn.getHostAddress()).thenReturn("hostaddress");
        when(dn.getId()).thenReturn("hostaddress");
        when(dn.getHostName()).thenReturn("hostaddress");
        when(cs.localNode()).thenReturn(dn);
        when(cs.getClusterName()).thenReturn(new ClusterName("cname"));
    }

    @Test
    public void testClusterHealthRequest() {
        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .build();
        AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
        TestAuditlogImpl.clear();
        al.logGrantedPrivileges("indices:data/read/search", new ClusterHealthRequest(), null);
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
    }

    @Test
    public void testSearchRequest() {

        SearchRequest sr = new SearchRequest();
        sr.indices("index1", "logstash*");

        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .build();
        AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
        TestAuditlogImpl.clear();
        al.logGrantedPrivileges("indices:data/read/search", sr, null);
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
    }

    @Test
    public void testSslException() {

        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
            .build();
        AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
        TestAuditlogImpl.clear();
        al.logSSLException(null, new Exception("test rest"));
        al.logSSLException(null, new Exception("test rest"), null, null);
        Assert.assertEquals(2, TestAuditlogImpl.messages.size());
    }

    @Test
    public void testRetry() {

        RetrySink.init();

        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", RetrySink.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
            .put(ConfigConstants.SECURITY_AUDIT_RETRY_COUNT, 10)
            .put(ConfigConstants.SECURITY_AUDIT_RETRY_DELAY_MS, 500)
            .build();
        AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
        al.logSSLException(null, new Exception("test retry"));
        Assert.assertNotNull(RetrySink.getMsg());
        Assert.assertTrue(RetrySink.getMsg().toJson().contains("test retry"));
    }

    @Test
    public void testNoRetry() {

        RetrySink.init();

        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", RetrySink.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
            .put(ConfigConstants.SECURITY_AUDIT_RETRY_COUNT, 0)
            .put(ConfigConstants.SECURITY_AUDIT_RETRY_DELAY_MS, 500)
            .build();
        AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
        al.logSSLException(null, new Exception("test retry"));
        Assert.assertNull(RetrySink.getMsg());
    }

    @Test
    public void testRestFilterEnabledCheck() {
        final Settings settings = Settings.builder().put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false).build();
        final AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
        for (AuditCategory category : AuditCategory.values()) {
            Assert.assertFalse(al.checkRestFilter(category, "user", mock(SecurityRequestChannel.class)));
        }
    }

    @Test
    public void testTransportFilterEnabledCheck() {
        final Settings settings = Settings.builder().put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false).build();
        final AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
        for (AuditCategory category : AuditCategory.values()) {
            Assert.assertFalse(al.checkTransportFilter(category, "action", "user", mock(TransportRequest.class)));
        }
    }

    @Test
    public void testTransportFilterMonitorActionsCheck() {
        final Settings settings = Settings.builder()
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
            .build();
        final AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, AbstractSecurityUnitTest.MOCK_POOL, null, cs);
        for (AuditCategory category : AuditCategory.values()) {
            Assert.assertTrue(al.checkTransportFilter(category, "cluster:monitor/any", "user", mock(TransportRequest.class)));
            Assert.assertTrue(al.checkTransportFilter(category, "indices:data/any", "user", mock(TransportRequest.class)));
            Assert.assertFalse(al.checkTransportFilter(category, "internal:any", "user", mock(TransportRequest.class)));

        }
    }
}
