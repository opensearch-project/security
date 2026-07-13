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

import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportChannel;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestHandler;

import org.mockito.ArgumentCaptor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AuditTransportInterceptorTest {

    private AuditLog auditLog;
    private ClusterService clusterService;
    private ThreadPool threadPool;
    private ThreadContext threadContext;
    private AuditTransportInterceptor interceptor;

    @Before
    public void setUp() {
        auditLog = mock(AuditLog.class);
        clusterService = mock(ClusterService.class);
        threadPool = mock(ThreadPool.class);
        threadContext = new ThreadContext(Settings.EMPTY);
        when(threadPool.getThreadContext()).thenReturn(threadContext);

        DiscoveryNode node = mock(DiscoveryNode.class);
        when(node.getHostAddress()).thenReturn("127.0.0.1");
        when(node.getId()).thenReturn("node-1-id");
        when(node.getHostName()).thenReturn("node-1-host");
        when(node.getName()).thenReturn("node-1");
        when(clusterService.localNode()).thenReturn(node);
        when(clusterService.getClusterName()).thenReturn(new ClusterName("test-cluster"));

        interceptor = new AuditTransportInterceptor(auditLog, clusterService, threadPool, Settings.EMPTY);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testLogsTransportEventWithCorrectFields() throws Exception {
        TransportRequest request = mock(TransportRequest.class);
        when(request.remoteAddress()).thenReturn(
            new TransportAddress(new InetSocketAddress(InetAddress.getByName("10.0.0.5"), 9300))
        );

        Task task = mock(Task.class);
        when(task.getId()).thenReturn(99L);
        when(task.getParentTaskId()).thenReturn(null);

        TransportChannel channel = mock(TransportChannel.class);
        TransportRequestHandler<TransportRequest> actualHandler = mock(TransportRequestHandler.class);

        TransportRequestHandler<TransportRequest> wrappedHandler = interceptor.interceptHandler(
            "indices:data/write/index", "generic", false, actualHandler
        );

        wrappedHandler.messageReceived(request, channel, task);

        // Verify audit event logged
        ArgumentCaptor<AuditMessage> captor = ArgumentCaptor.forClass(AuditMessage.class);
        verify(auditLog).logTransportAudit(captor.capture());

        AuditMessage msg = captor.getValue();
        Map<String, Object> fields = msg.getAsMap();

        assertThat(msg.getCategory(), equalTo(AuditCategory.TRANSPORT_AUDIT));
        assertThat(msg.getPrivilege(), equalTo("indices:data/write/index"));
        assertThat(fields.get(AuditMessage.REMOTE_ADDRESS), notNullValue());
        assertThat(fields.get(AuditMessage.TASK_ID), equalTo("node-1-id:99"));

        // Verify actual handler still called (non-blocking)
        verify(actualHandler).messageReceived(request, channel, task);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testSkipsInternalActions() throws Exception {
        TransportRequest request = mock(TransportRequest.class);
        TransportChannel channel = mock(TransportChannel.class);
        Task task = mock(Task.class);
        TransportRequestHandler<TransportRequest> actualHandler = mock(TransportRequestHandler.class);

        TransportRequestHandler<TransportRequest> wrappedHandler = interceptor.interceptHandler(
            "internal:coordination/fault_detection/follower_check", "generic", false, actualHandler
        );

        wrappedHandler.messageReceived(request, channel, task);

        // Should NOT log audit event for internal actions
        verify(auditLog, never()).logTransportAudit(org.mockito.ArgumentMatchers.any());

        // But should still call actual handler
        verify(actualHandler).messageReceived(request, channel, task);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testSkipsClusterMonitorActions() throws Exception {
        TransportRequest request = mock(TransportRequest.class);
        TransportChannel channel = mock(TransportChannel.class);
        Task task = mock(Task.class);
        TransportRequestHandler<TransportRequest> actualHandler = mock(TransportRequestHandler.class);

        TransportRequestHandler<TransportRequest> wrappedHandler = interceptor.interceptHandler(
            "cluster:monitor/nodes/stats", "generic", false, actualHandler
        );

        wrappedHandler.messageReceived(request, channel, task);

        verify(auditLog, never()).logTransportAudit(org.mockito.ArgumentMatchers.any());
        verify(actualHandler).messageReceived(request, channel, task);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testSkipsIndicesMonitorActions() throws Exception {
        TransportRequest request = mock(TransportRequest.class);
        TransportChannel channel = mock(TransportChannel.class);
        Task task = mock(Task.class);
        TransportRequestHandler<TransportRequest> actualHandler = mock(TransportRequestHandler.class);

        TransportRequestHandler<TransportRequest> wrappedHandler = interceptor.interceptHandler(
            "indices:monitor/stats", "generic", false, actualHandler
        );

        wrappedHandler.messageReceived(request, channel, task);

        verify(auditLog, never()).logTransportAudit(org.mockito.ArgumentMatchers.any());
        verify(actualHandler).messageReceived(request, channel, task);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testIncludesUserIdentityFromThreadContext() throws Exception {
        User user = new User("admin");
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);

        TransportRequest request = mock(TransportRequest.class);
        when(request.remoteAddress()).thenReturn(null);

        TransportChannel channel = mock(TransportChannel.class);
        Task task = mock(Task.class);
        when(task.getId()).thenReturn(1L);
        when(task.getParentTaskId()).thenReturn(null);
        TransportRequestHandler<TransportRequest> actualHandler = mock(TransportRequestHandler.class);

        TransportRequestHandler<TransportRequest> wrappedHandler = interceptor.interceptHandler(
            "indices:data/read/search", "generic", false, actualHandler
        );

        wrappedHandler.messageReceived(request, channel, task);

        ArgumentCaptor<AuditMessage> captor = ArgumentCaptor.forClass(AuditMessage.class);
        verify(auditLog).logTransportAudit(captor.capture());

        AuditMessage msg = captor.getValue();
        assertThat(msg.getEffectiveUser(), equalTo("admin"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testIncludesSslPrincipalWhenNoUser() throws Exception {
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL, "CN=node-2,OU=cluster,O=org");

        TransportRequest request = mock(TransportRequest.class);
        when(request.remoteAddress()).thenReturn(null);

        TransportChannel channel = mock(TransportChannel.class);
        Task task = mock(Task.class);
        when(task.getId()).thenReturn(1L);
        when(task.getParentTaskId()).thenReturn(null);
        TransportRequestHandler<TransportRequest> actualHandler = mock(TransportRequestHandler.class);

        TransportRequestHandler<TransportRequest> wrappedHandler = interceptor.interceptHandler(
            "indices:data/write/index", "generic", false, actualHandler
        );

        wrappedHandler.messageReceived(request, channel, task);

        ArgumentCaptor<AuditMessage> captor = ArgumentCaptor.forClass(AuditMessage.class);
        verify(auditLog).logTransportAudit(captor.capture());

        AuditMessage msg = captor.getValue();
        assertThat(msg.getEffectiveUser(), equalTo("CN=node-2,OU=cluster,O=org"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testNoIdentityWhenNothingInThreadContext() throws Exception {
        TransportRequest request = mock(TransportRequest.class);
        when(request.remoteAddress()).thenReturn(null);

        TransportChannel channel = mock(TransportChannel.class);
        Task task = mock(Task.class);
        when(task.getId()).thenReturn(1L);
        when(task.getParentTaskId()).thenReturn(null);
        TransportRequestHandler<TransportRequest> actualHandler = mock(TransportRequestHandler.class);

        TransportRequestHandler<TransportRequest> wrappedHandler = interceptor.interceptHandler(
            "indices:data/read/search", "generic", false, actualHandler
        );

        wrappedHandler.messageReceived(request, channel, task);

        ArgumentCaptor<AuditMessage> captor = ArgumentCaptor.forClass(AuditMessage.class);
        verify(auditLog).logTransportAudit(captor.capture());

        AuditMessage msg = captor.getValue();
        assertNull(msg.getEffectiveUser());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testFallsBackToThreadContextRemoteAddress() throws Exception {
        TransportRequest request = mock(TransportRequest.class);
        when(request.remoteAddress()).thenReturn(null);

        TransportAddress contextAddress = new TransportAddress(new InetSocketAddress(InetAddress.getByName("192.168.1.50"), 9300));
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, contextAddress);

        TransportChannel channel = mock(TransportChannel.class);
        Task task = mock(Task.class);
        when(task.getId()).thenReturn(5L);
        when(task.getParentTaskId()).thenReturn(null);
        TransportRequestHandler<TransportRequest> actualHandler = mock(TransportRequestHandler.class);

        TransportRequestHandler<TransportRequest> wrappedHandler = interceptor.interceptHandler(
            "indices:data/write/index", "generic", false, actualHandler
        );

        wrappedHandler.messageReceived(request, channel, task);

        ArgumentCaptor<AuditMessage> captor = ArgumentCaptor.forClass(AuditMessage.class);
        verify(auditLog).logTransportAudit(captor.capture());

        AuditMessage msg = captor.getValue();
        Map<String, Object> fields = msg.getAsMap();
        assertThat(fields.get(AuditMessage.REMOTE_ADDRESS), notNullValue());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testHandlerStillCalledWhenAuditThrows() throws Exception {
        TransportRequest request = mock(TransportRequest.class);
        when(request.remoteAddress()).thenReturn(null);
        // Force clusterService to throw during message construction
        when(clusterService.getClusterName()).thenThrow(new RuntimeException("simulated failure"));

        TransportChannel channel = mock(TransportChannel.class);
        Task task = mock(Task.class);
        when(task.getId()).thenReturn(1L);
        when(task.getParentTaskId()).thenReturn(null);
        TransportRequestHandler<TransportRequest> actualHandler = mock(TransportRequestHandler.class);

        TransportRequestHandler<TransportRequest> wrappedHandler = interceptor.interceptHandler(
            "indices:data/read/search", "generic", false, actualHandler
        );

        wrappedHandler.messageReceived(request, channel, task);

        // Handler still called despite audit failure
        verify(actualHandler).messageReceived(request, channel, task);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testNullTaskHandledGracefully() throws Exception {
        TransportRequest request = mock(TransportRequest.class);
        when(request.remoteAddress()).thenReturn(null);

        TransportChannel channel = mock(TransportChannel.class);
        TransportRequestHandler<TransportRequest> actualHandler = mock(TransportRequestHandler.class);

        TransportRequestHandler<TransportRequest> wrappedHandler = interceptor.interceptHandler(
            "indices:data/read/search", "generic", false, actualHandler
        );

        wrappedHandler.messageReceived(request, channel, null);

        ArgumentCaptor<AuditMessage> captor = ArgumentCaptor.forClass(AuditMessage.class);
        verify(auditLog).logTransportAudit(captor.capture());

        AuditMessage msg = captor.getValue();
        Map<String, Object> fields = msg.getAsMap();
        assertNull(fields.get(AuditMessage.TASK_ID));

        verify(actualHandler).messageReceived(request, channel, null);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testLogsReplicaWriteAction() throws Exception {
        // Replica writes use action names like "indices:data/write/bulk[s][r]"
        TransportRequest request = mock(TransportRequest.class);
        when(request.remoteAddress()).thenReturn(
            new TransportAddress(new InetSocketAddress(InetAddress.getByName("10.0.0.2"), 9300))
        );

        Task task = mock(Task.class);
        when(task.getId()).thenReturn(200L);
        when(task.getParentTaskId()).thenReturn(null);

        TransportChannel channel = mock(TransportChannel.class);
        TransportRequestHandler<TransportRequest> actualHandler = mock(TransportRequestHandler.class);

        TransportRequestHandler<TransportRequest> wrappedHandler = interceptor.interceptHandler(
            "indices:data/write/bulk[s][r]", "generic", false, actualHandler
        );

        wrappedHandler.messageReceived(request, channel, task);

        ArgumentCaptor<AuditMessage> captor = ArgumentCaptor.forClass(AuditMessage.class);
        verify(auditLog).logTransportAudit(captor.capture());

        AuditMessage msg = captor.getValue();
        assertThat(msg.getCategory(), equalTo(AuditCategory.TRANSPORT_AUDIT));
        assertThat(msg.getPrivilege(), equalTo("indices:data/write/bulk[s][r]"));

        verify(actualHandler).messageReceived(request, channel, task);
    }
}
