/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.auditlog.sink;

import org.junit.Test;

import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.index.IndexAction;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexRequestBuilder;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AbstractInternalOpenSearchSinkTest {
    @Test
    public void auditWritesDoNotForceRefresh() throws Exception {
        // Regular indices use INDEX; data streams use CREATE through the same sink implementation.
        for (DocWriteRequest.OpType opType : new DocWriteRequest.OpType[] { DocWriteRequest.OpType.INDEX, DocWriteRequest.OpType.CREATE }) {
            ThreadContext context = new ThreadContext(Settings.EMPTY);
            Client client = mock(Client.class);
            ThreadPool threadPool = mock(ThreadPool.class);
            when(threadPool.getThreadContext()).thenReturn(context);
            IndexRequestBuilder builder = new IndexRequestBuilder(client, IndexAction.INSTANCE, "audit-test");
            when(client.prepareIndex("audit-test")).thenReturn(builder);
            @SuppressWarnings("unchecked")
            ActionFuture<IndexResponse> future = mock(ActionFuture.class);
            when(client.execute(eq(IndexAction.INSTANCE), any(IndexRequest.class))).thenReturn(future);
            ClusterService clusterService = mock(ClusterService.class);
            when(clusterService.localNode()).thenReturn(mock(DiscoveryNode.class));
            when(clusterService.getClusterName()).thenReturn(new ClusterName("audit-test"));
            AuditMessage message = new AuditMessage(AuditCategory.FAILED_LOGIN, clusterService, null, null);

            AbstractInternalOpenSearchSink sink = new AbstractInternalOpenSearchSink(
                "test",
                Settings.EMPTY,
                null,
                client,
                threadPool,
                null,
                opType,
                null
            ) {
                @Override
                protected boolean createIndexIfAbsent(String indexName) {
                    return true;
                }

                @Override
                protected boolean doStore(AuditMessage msg) {
                    return doStore(msg, "audit-test");
                }
            };
            assertTrue(sink.doStore(message, "audit-test"));
            assertEquals(RefreshPolicy.NONE, builder.request().getRefreshPolicy());
            assertEquals(opType, builder.request().opType());
            verify(client).execute(IndexAction.INSTANCE, builder.request());
            verify(future).actionGet();
        }
    }
}
