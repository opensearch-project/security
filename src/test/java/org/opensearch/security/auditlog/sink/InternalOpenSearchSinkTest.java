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

package org.opensearch.security.auditlog.sink;

import java.nio.file.Path;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class InternalOpenSearchSinkTest {

    @Mock
    private Client client;
    @Mock
    private AdminClient adminClient;
    @Mock
    private IndicesAdminClient indicesAdminClient;
    @Mock
    private ThreadPool threadPool;
    @Mock
    private ClusterService clusterService;
    @Mock
    private ClusterState clusterState;
    @Mock
    private Metadata metadata;
    @Mock
    private Path configPath;

    private InternalOpenSearchSink sink;

    @Before
    public void setUp() {
        when(clusterService.state()).thenReturn(clusterState);
        when(clusterState.metadata()).thenReturn(metadata);
        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);

        Settings settings = Settings.builder()
            .put("plugins.security.audit.config.index", "test-audit-index")
            .build();

        sink = new InternalOpenSearchSink(
            "test",
            settings,
            "plugins.security.audit.config",
            configPath,
            client,
            threadPool,
            null,
            clusterService
        );
    }

    @Test
    public void testCreateIndexIfAbsent_IndexExists() {
        when(metadata.hasIndex("test-index")).thenReturn(true);

        boolean result = sink.createIndexIfAbsent("test-index");

        assertTrue(result);
        verify(indicesAdminClient, never()).create(any(CreateIndexRequest.class));
    }

    @Test
    public void testCreateIndexIfAbsent_AliasExists() {
        when(metadata.hasIndex("test-alias")).thenReturn(false);
        when(metadata.hasAlias("test-alias")).thenReturn(true);

        boolean result = sink.createIndexIfAbsent("test-alias");

        assertTrue(result);
        verify(indicesAdminClient, never()).create(any(CreateIndexRequest.class));
    }

    @Test
    public void testCreateIndexIfAbsent_NeitherExists_CreatesIndex() {
        when(metadata.hasIndex("new-index")).thenReturn(false);
        when(metadata.hasAlias("new-index")).thenReturn(false);

        CreateIndexResponse createIndexResponse = new CreateIndexResponse(true, true, "new-index");
        PlainActionFuture<CreateIndexResponse> future = PlainActionFuture.newFuture();
        future.onResponse(createIndexResponse);
        when(indicesAdminClient.create(any(CreateIndexRequest.class))).thenReturn(future);

        boolean result = sink.createIndexIfAbsent("new-index");

        assertTrue(result);
        verify(indicesAdminClient).create(any(CreateIndexRequest.class));
    }
}
