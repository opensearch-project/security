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

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.ArgumentCaptor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AuditActionFilterTest {

    private AuditLog auditLog;
    private ClusterService clusterService;
    private ThreadPool threadPool;
    private AuditActionFilter filter;

    @Before
    public void setUp() {
        auditLog = mock(AuditLog.class);
        clusterService = mock(ClusterService.class);
        threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(org.opensearch.common.settings.Settings.EMPTY));

        DiscoveryNode node = mock(DiscoveryNode.class);
        when(node.getHostAddress()).thenReturn("127.0.0.1");
        when(node.getId()).thenReturn("node-1-id");
        when(node.getHostName()).thenReturn("node-1-host");
        when(node.getName()).thenReturn("node-1");
        when(clusterService.localNode()).thenReturn(node);
        when(clusterService.getClusterName()).thenReturn(new ClusterName("test-cluster"));

        filter = new AuditActionFilter(
            auditLog,
            clusterService,
            threadPool,
            AuditConfig.Filter.DEFAULT,
            new org.opensearch.cluster.metadata.IndexNameExpressionResolver(threadPool.getThreadContext()),
            "security-auditlog"
        );
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

    @SuppressWarnings("unchecked")
    @Test
    public void testApplyIncludesSslPrincipalAsEffectiveUser() throws Exception {
        // Simulate REST wrapper having stored the SSL principal in ThreadContext
        threadPool.getThreadContext()
            .putTransient(org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL, "CN=admin,OU=client,O=org");

        ClusterHealthRequest request = new ClusterHealthRequest();
        ActionFilterChain<ClusterHealthRequest, ActionResponse> chain = mock(ActionFilterChain.class);
        ActionListener<ActionResponse> listener = mock(ActionListener.class);

        filter.apply(null, "cluster:monitor/health", request, ActionRequestMetadata.empty(), listener, chain);

        ArgumentCaptor<AuditMessage> captor = ArgumentCaptor.forClass(AuditMessage.class);
        verify(auditLog).logRequestAudit(captor.capture());

        AuditMessage msg = captor.getValue();
        assertThat(msg.getEffectiveUser(), equalTo("CN=admin,OU=client,O=org"));

        verify(chain).proceed(null, "cluster:monitor/health", request, listener);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testApplyWithoutSslPrincipalHasNoEffectiveUser() throws Exception {
        // No SSL principal in ThreadContext — effective_user should be absent
        ClusterHealthRequest request = new ClusterHealthRequest();
        ActionFilterChain<ClusterHealthRequest, ActionResponse> chain = mock(ActionFilterChain.class);
        ActionListener<ActionResponse> listener = mock(ActionListener.class);

        filter.apply(null, "cluster:monitor/health", request, ActionRequestMetadata.empty(), listener, chain);

        ArgumentCaptor<AuditMessage> captor = ArgumentCaptor.forClass(AuditMessage.class);
        verify(auditLog).logRequestAudit(captor.capture());

        AuditMessage msg = captor.getValue();
        assertThat(msg.getEffectiveUser(), equalTo(null));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testSkipsInternalActions() throws Exception {
        SearchRequest request = new SearchRequest("my-index");
        ActionFilterChain<SearchRequest, ActionResponse> chain = mock(ActionFilterChain.class);
        ActionListener<ActionResponse> listener = mock(ActionListener.class);

        filter.apply(null, "internal:coordination/fault_detection/follower_check", request, ActionRequestMetadata.empty(), listener, chain);

        // Should NOT log audit event for internal actions
        verify(auditLog, never()).logRequestAudit(any());

        // But chain should still proceed
        verify(chain).proceed(null, "internal:coordination/fault_detection/follower_check", request, listener);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testChainContinuesWhenAuditThrows() throws Exception {
        // Force auditLog.logRequestAudit to throw
        doThrow(new RuntimeException("simulated audit failure")).when(auditLog).logRequestAudit(any());

        ClusterHealthRequest request = new ClusterHealthRequest();
        ActionFilterChain<ClusterHealthRequest, ActionResponse> chain = mock(ActionFilterChain.class);
        ActionListener<ActionResponse> listener = mock(ActionListener.class);

        filter.apply(null, "cluster:monitor/health", request, ActionRequestMetadata.empty(), listener, chain);

        // Chain should still proceed despite audit failure
        verify(chain).proceed(null, "cluster:monitor/health", request, listener);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testIncludesFgacUserFromThreadContext() throws Exception {
        // Simulate FGAC mode where BackendRegistry has populated the user
        User fgacUser = new User("admin_user");
        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, fgacUser);

        ClusterHealthRequest request = new ClusterHealthRequest();
        ActionFilterChain<ClusterHealthRequest, ActionResponse> chain = mock(ActionFilterChain.class);
        ActionListener<ActionResponse> listener = mock(ActionListener.class);

        filter.apply(null, "cluster:monitor/health", request, ActionRequestMetadata.empty(), listener, chain);

        ArgumentCaptor<AuditMessage> captor = ArgumentCaptor.forClass(AuditMessage.class);
        verify(auditLog).logRequestAudit(captor.capture());

        AuditMessage msg = captor.getValue();
        // FGAC user takes priority over SSL principal
        assertThat(msg.getEffectiveUser(), equalTo("admin_user"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testFgacUserTakesPriorityOverSslPrincipal() throws Exception {
        // Both SSL principal and FGAC user present — user wins
        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL, "CN=node-cert,O=org");
        User fgacUser = new User("real_user");
        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, fgacUser);

        ClusterHealthRequest request = new ClusterHealthRequest();
        ActionFilterChain<ClusterHealthRequest, ActionResponse> chain = mock(ActionFilterChain.class);
        ActionListener<ActionResponse> listener = mock(ActionListener.class);

        filter.apply(null, "cluster:monitor/health", request, ActionRequestMetadata.empty(), listener, chain);

        ArgumentCaptor<AuditMessage> captor = ArgumentCaptor.forClass(AuditMessage.class);
        verify(auditLog).logRequestAudit(captor.capture());

        AuditMessage msg = captor.getValue();
        assertThat(msg.getEffectiveUser(), equalTo("real_user"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testIgnoreUsersSuppressesMatchingUser() throws Exception {
        Settings ignoreSettings = Settings.builder()
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, "ignored_admin")
            .build();
        AuditActionFilter ignoreFilter = new AuditActionFilter(
            auditLog,
            clusterService,
            threadPool,
            AuditConfig.from(ignoreSettings).getFilter(),
            new org.opensearch.cluster.metadata.IndexNameExpressionResolver(threadPool.getThreadContext()),
            "security-auditlog"
        );

        User ignoredUser = new User("ignored_admin");
        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, ignoredUser);

        ClusterHealthRequest request = new ClusterHealthRequest();
        ActionFilterChain<ClusterHealthRequest, ActionResponse> chain = mock(ActionFilterChain.class);
        ActionListener<ActionResponse> listener = mock(ActionListener.class);

        ignoreFilter.apply(null, "cluster:monitor/health", request, ActionRequestMetadata.empty(), listener, chain);

        // Should NOT log audit event for ignored user
        verify(auditLog, never()).logRequestAudit(any());
        // But chain should still proceed
        verify(chain).proceed(null, "cluster:monitor/health", request, listener);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testIgnoreRequestsSuppressesMatchingAction() throws Exception {
        Settings ignoreSettings = Settings.builder()
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS, "indices:data/read/search")
            .build();
        AuditActionFilter ignoreFilter = new AuditActionFilter(
            auditLog,
            clusterService,
            threadPool,
            AuditConfig.from(ignoreSettings).getFilter(),
            new org.opensearch.cluster.metadata.IndexNameExpressionResolver(threadPool.getThreadContext()),
            "security-auditlog"
        );

        SearchRequest request = new SearchRequest("my-index");
        ActionFilterChain<SearchRequest, ActionResponse> chain = mock(ActionFilterChain.class);
        ActionListener<ActionResponse> listener = mock(ActionListener.class);

        ignoreFilter.apply(null, "indices:data/read/search", request, ActionRequestMetadata.empty(), listener, chain);

        // Should NOT log audit event for ignored action
        verify(auditLog, never()).logRequestAudit(any());
        // But chain should still proceed
        verify(chain).proceed(null, "indices:data/read/search", request, listener);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testIgnoreRequestsMatchesByClassName() throws Exception {
        Settings ignoreSettings = Settings.builder()
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS, "SearchRequest")
            .build();
        AuditActionFilter ignoreFilter = new AuditActionFilter(
            auditLog,
            clusterService,
            threadPool,
            AuditConfig.from(ignoreSettings).getFilter(),
            new org.opensearch.cluster.metadata.IndexNameExpressionResolver(threadPool.getThreadContext()),
            "security-auditlog"
        );

        SearchRequest request = new SearchRequest("my-index");
        ActionFilterChain<SearchRequest, ActionResponse> chain = mock(ActionFilterChain.class);
        ActionListener<ActionResponse> listener = mock(ActionListener.class);

        ignoreFilter.apply(null, "indices:data/read/search", request, ActionRequestMetadata.empty(), listener, chain);

        // Should NOT log — class name "SearchRequest" matches
        verify(auditLog, never()).logRequestAudit(any());
        verify(chain).proceed(null, "indices:data/read/search", request, listener);
    }

    // =====================================================================
    // Self-loop guard — null/empty prefix safety
    // =====================================================================

    @SuppressWarnings("unchecked")
    @Test
    public void testSelfLoopGuardSuppressesAuditIndexWrites() throws Exception {
        // Request targeting the audit index should be skipped
        SearchRequest request = new SearchRequest("security-auditlog-2026.07.16");
        ActionFilterChain<SearchRequest, ActionResponse> chain = mock(ActionFilterChain.class);
        ActionListener<ActionResponse> listener = mock(ActionListener.class);

        filter.apply(null, "indices:data/read/search", request, ActionRequestMetadata.empty(), listener, chain);

        // Should NOT log — request targets audit index
        verify(auditLog, never()).logRequestAudit(any());
        // Chain should still proceed
        verify(chain).proceed(null, "indices:data/read/search", request, listener);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testNullPrefixDoesNotSuppressEvents() throws Exception {
        // Construct filter with null prefix — should still log events (guard disabled)
        AuditActionFilter nullPrefixFilter = new AuditActionFilter(
            auditLog,
            clusterService,
            threadPool,
            AuditConfig.Filter.DEFAULT,
            new org.opensearch.cluster.metadata.IndexNameExpressionResolver(threadPool.getThreadContext()),
            null
        );

        SearchRequest request = new SearchRequest("security-auditlog-2026.07.16");
        ActionFilterChain<SearchRequest, ActionResponse> chain = mock(ActionFilterChain.class);
        ActionListener<ActionResponse> listener = mock(ActionListener.class);

        nullPrefixFilter.apply(null, "indices:data/read/search", request, ActionRequestMetadata.empty(), listener, chain);

        // Should still log — null prefix disables guard, doesn't suppress everything
        verify(auditLog).logRequestAudit(any());
        verify(chain).proceed(null, "indices:data/read/search", request, listener);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testEmptyPrefixDoesNotSuppressEvents() throws Exception {
        // Construct filter with empty prefix — should still log events (guard disabled)
        AuditActionFilter emptyPrefixFilter = new AuditActionFilter(
            auditLog,
            clusterService,
            threadPool,
            AuditConfig.Filter.DEFAULT,
            new org.opensearch.cluster.metadata.IndexNameExpressionResolver(threadPool.getThreadContext()),
            ""
        );

        SearchRequest request = new SearchRequest("any-index");
        ActionFilterChain<SearchRequest, ActionResponse> chain = mock(ActionFilterChain.class);
        ActionListener<ActionResponse> listener = mock(ActionListener.class);

        emptyPrefixFilter.apply(null, "indices:data/read/search", request, ActionRequestMetadata.empty(), listener, chain);

        // Should still log — empty prefix disables guard, doesn't suppress everything
        verify(auditLog).logRequestAudit(any());
        verify(chain).proceed(null, "indices:data/read/search", request, listener);
    }

    @Test
    public void testConstructorLogsWarnWhenPrefixIsNull() {
        Logger logger = (Logger) LogManager.getLogger(AuditActionFilter.class);
        Appender mockAppender = mock(Appender.class);
        when(mockAppender.getName()).thenReturn("MockAppender");
        when(mockAppender.isStarted()).thenReturn(true);
        ArgumentCaptor<LogEvent> logCaptor = ArgumentCaptor.forClass(LogEvent.class);
        doNothing().when(mockAppender).append(logCaptor.capture());
        logger.addAppender(mockAppender);
        logger.setLevel(Level.WARN);

        try {
            new AuditActionFilter(
                auditLog,
                clusterService,
                threadPool,
                AuditConfig.Filter.DEFAULT,
                new org.opensearch.cluster.metadata.IndexNameExpressionResolver(threadPool.getThreadContext()),
                null
            );

            boolean foundWarning = logCaptor.getAllValues()
                .stream()
                .anyMatch(
                    event -> event.getLevel() == Level.WARN
                        && event.getMessage().getFormattedMessage().contains("Audit index prefix is null or empty")
                );
            assertTrue("Expected WARN about null/empty audit index prefix", foundWarning);
        } finally {
            logger.removeAppender(mockAppender);
        }
    }

    @Test
    public void testConstructorLogsWarnWhenPrefixIsEmpty() {
        Logger logger = (Logger) LogManager.getLogger(AuditActionFilter.class);
        Appender mockAppender = mock(Appender.class);
        when(mockAppender.getName()).thenReturn("MockAppender");
        when(mockAppender.isStarted()).thenReturn(true);
        ArgumentCaptor<LogEvent> logCaptor = ArgumentCaptor.forClass(LogEvent.class);
        doNothing().when(mockAppender).append(logCaptor.capture());
        logger.addAppender(mockAppender);
        logger.setLevel(Level.WARN);

        try {
            new AuditActionFilter(
                auditLog,
                clusterService,
                threadPool,
                AuditConfig.Filter.DEFAULT,
                new org.opensearch.cluster.metadata.IndexNameExpressionResolver(threadPool.getThreadContext()),
                ""
            );

            boolean foundWarning = logCaptor.getAllValues()
                .stream()
                .anyMatch(
                    event -> event.getLevel() == Level.WARN
                        && event.getMessage().getFormattedMessage().contains("Audit index prefix is null or empty")
                );
            assertTrue("Expected WARN about null/empty audit index prefix", foundWarning);
        } finally {
            logger.removeAppender(mockAppender);
        }
    }

    // =====================================================================
    // getAuditIndexPrefix — self-loop guard prefix extraction
    // =====================================================================

    @Test
    public void testGetAuditIndexPrefixExtractsFromJodaPattern() {
        Settings settings = Settings.builder().put("plugins.security.audit.config.index", "'my-custom-audit-'YYYY.MM.dd").build();
        assertThat(OpenSearchSecurityPlugin.getAuditIndexPrefix(settings), equalTo("my-custom-audit-"));
    }

    @Test
    public void testGetAuditIndexPrefixUsesDefaultWhenNotConfigured() {
        Settings settings = Settings.EMPTY;
        assertThat(OpenSearchSecurityPlugin.getAuditIndexPrefix(settings), equalTo("security-auditlog-"));
    }

    @Test
    public void testGetAuditIndexPrefixHandlesPlainIndexName() {
        Settings settings = Settings.builder().put("plugins.security.audit.config.index", "static-audit-index").build();
        // No quotes — datastream fallback not set, returns raw pattern
        assertThat(OpenSearchSecurityPlugin.getAuditIndexPrefix(settings), equalTo("static-audit-index"));
    }

    @Test
    public void testGetAuditIndexPrefixFallsBackToDatastreamName() {
        Settings settings = Settings.builder()
            .put("plugins.security.audit.config.index", "no-quotes-here")
            .put("plugins.security.audit.config.data_stream.name", "opensearch-security-auditlog")
            .build();
        assertThat(OpenSearchSecurityPlugin.getAuditIndexPrefix(settings), equalTo("opensearch-security-auditlog"));
    }

    @Test
    public void testGetAuditIndexPrefixNoQuotesNoDatastreamReturnsRawPattern() {
        // Edge case: Joda pattern without quotes (e.g., "audit-YYYY.MM.dd")
        // Falls back to raw pattern — self-loop guard will use this as prefix.
        // This is a known limitation: the prefix won't match resolved index names.
        Settings settings = Settings.builder().put("plugins.security.audit.config.index", "audit-YYYY.MM.dd").build();
        assertThat(OpenSearchSecurityPlugin.getAuditIndexPrefix(settings), equalTo("audit-YYYY.MM.dd"));
    }
}
