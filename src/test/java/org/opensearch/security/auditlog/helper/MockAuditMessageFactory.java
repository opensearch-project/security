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

package org.opensearch.security.auditlog.helper;

import java.net.InetSocketAddress;

import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MockAuditMessageFactory {

    public static AuditMessage validAuditMessage() {
        return validAuditMessage(AuditCategory.FAILED_LOGIN);
    }

    public static AuditMessage validAuditMessage(AuditCategory category) {

        ClusterService cs = mock(ClusterService.class);
        DiscoveryNode dn = mock(DiscoveryNode.class);

        when(dn.getHostAddress()).thenReturn("hostaddress");
        when(dn.getId()).thenReturn("hostaddress");
        when(dn.getHostName()).thenReturn("hostaddress");
        when(cs.localNode()).thenReturn(dn);
        when(cs.getClusterName()).thenReturn(new ClusterName("testcluster"));

        TransportAddress ta = new TransportAddress(new InetSocketAddress("8.8.8.8", 80));

        AuditMessage msg = new AuditMessage(category, cs, Origin.TRANSPORT, Origin.TRANSPORT);
        msg.addEffectiveUser("John Doe");
        msg.addRemoteAddress(ta);
        msg.addRequestType("IndexRequest");
        return msg;
    }

}
