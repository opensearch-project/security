/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.filter;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.tasks.Task;

import org.mockito.ArgumentCaptor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AuditActionFilterTest {

    private AuditLog auditLog;
    private ClusterService clusterService;
    private AuditActionFilter filter;

    @Before
    public void setUp() {
        auditLog = mock(AuditLog.class);
        clusterService = mock(ClusterService.class);

        DiscoveryNode node = mock(DiscoveryNode.class);
        when(node.getHostAddress()).thenReturn("127.0.0.1");
        when(node.getId()).thenReturn("node-1-id");
        when(node.getHostName()).thenReturn("node-1-host");
        when(node.getName()).thenReturn("node-1");
        when(clusterService.localNode()).thenReturn(node);
        when(clusterService.getClusterName()).thenReturn(new ClusterName("test-cluster"));

        filter = new AuditActionFilter(auditLog, clusterService);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testApplyLogsCorrectFields() throws Exception {
        // Setup request with remote address and indices
        SearchRequest request = new SearchRequest("my-index", "logs-*");
        request.remoteAddress(new TransportAddress(new InetSocketAddress(InetAddress.getByName("192.168.1.10"), 54321)));

        Task task = mock(Task.class);
        when(task.getId()).thenReturn(42L);
        when(task.getParentTaskId()).thenReturn(null);

        ActionFilterChain<SearchRequest, ActionResponse> chain = mock(ActionFilterChain.class);
        ActionListener<ActionResponse> listener = mock(ActionListener.class);

        // Act
        filter.apply(task, "indices:data/read/search", request, ActionRequestMetadata.empty(), listener, chain);

        // Verify audit message was logged
        ArgumentCaptor<AuditMessage> captor = ArgumentCaptor.forClass(AuditMessage.class);
        verify(auditLog).logRequestAudit(captor.capture());

        AuditMessage msg = captor.getValue();
        Map<String, Object> fields = msg.getAsMap();

        // Verify category
        assertThat(msg.getCategory(), equalTo(AuditCategory.REQUEST_AUDIT));

        // Verify fields from request
        assertThat(msg.getPrivilege(), equalTo("indices:data/read/search"));
        assertThat(msg.getRequestType(), equalTo("SearchRequest"));
        assertThat((String[]) fields.get(AuditMessage.INDICES), arrayContaining("my-index", "logs-*"));
        assertThat(fields.get(AuditMessage.REMOTE_ADDRESS), notNullValue());

        // Verify node/cluster info from ClusterService
        assertThat(fields.get(AuditMessage.NODE_NAME), equalTo("node-1"));
        assertThat(fields.get(AuditMessage.NODE_ID), equalTo("node-1-id"));
        assertThat(fields.get(AuditMessage.CLUSTER_NAME), equalTo("test-cluster"));

        // Verify task ID (format is nodeId:taskId)
        assertThat(fields.get(AuditMessage.TASK_ID), equalTo("node-1-id:42"));

        // Verify chain continues
        verify(chain).proceed(task, "indices:data/read/search", request, listener);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testApplyWithNonIndicesRequest() throws Exception {
        // A request that doesn't implement IndicesRequest (e.g., cluster health)
        ClusterHealthRequest request = new ClusterHealthRequest();

        ActionFilterChain<ClusterHealthRequest, ActionResponse> chain = mock(ActionFilterChain.class);
        ActionListener<ActionResponse> listener = mock(ActionListener.class);

        filter.apply(null, "cluster:monitor/health", request, ActionRequestMetadata.empty(), listener, chain);

        ArgumentCaptor<AuditMessage> captor = ArgumentCaptor.forClass(AuditMessage.class);
        verify(auditLog).logRequestAudit(captor.capture());

        AuditMessage msg = captor.getValue();
        Map<String, Object> fields = msg.getAsMap();

        assertThat(msg.getCategory(), equalTo(AuditCategory.REQUEST_AUDIT));
        assertThat(msg.getPrivilege(), equalTo("cluster:monitor/health"));
        assertThat(msg.getRequestType(), equalTo("ClusterHealthRequest"));
        // No indices field since it's not an IndicesRequest
        assertThat(fields.get(AuditMessage.INDICES), equalTo(null));
        // No task ID since task is null
        assertThat(fields.get(AuditMessage.TASK_ID), equalTo(null));

        verify(chain).proceed(null, "cluster:monitor/health", request, listener);
    }
}
