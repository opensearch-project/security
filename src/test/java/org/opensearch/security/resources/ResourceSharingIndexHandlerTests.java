/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateRequestBuilder;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.index.get.GetResult;
import org.opensearch.security.resources.sharing.ResourceSharing;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the workspace-related read/write helpers on {@link ResourceSharingIndexHandler}:
 * {@link ResourceSharingIndexHandler#fetchSharingInfoForIds} and
 * {@link ResourceSharingIndexHandler#backfillWorkspacesOnExisting}.
 */
public class ResourceSharingIndexHandlerTests {

    private static final String RESOURCE_INDEX = "test-index";

    private Client client;
    private ResourceSharingIndexHandler handler;

    @Before
    public void setUp() {
        client = mock(Client.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));
        handler = new ResourceSharingIndexHandler(client, threadPool, mock(ResourcePluginInfo.class));
    }

    private MultiGetItemResponse existingItem(String id, String sourceJson) {
        GetResult getResult = mock(GetResult.class);
        when(getResult.getId()).thenReturn(id);
        when(getResult.isExists()).thenReturn(true);
        byte[] bytes = sourceJson.getBytes(StandardCharsets.UTF_8);
        when(getResult.sourceRef()).thenReturn(new BytesArray(bytes, 0, bytes.length));
        when(getResult.sourceAsString()).thenReturn(sourceJson);
        return new MultiGetItemResponse(new GetResponse(getResult), null);
    }

    private void stubGet(String id, boolean exists, String sourceJson) {
        doAnswer(inv -> {
            ActionListener<GetResponse> l = inv.getArgument(1);
            GetResult getResult = mock(GetResult.class);
            when(getResult.getId()).thenReturn(id);
            when(getResult.isExists()).thenReturn(exists);
            if (exists) {
                byte[] bytes = sourceJson.getBytes(StandardCharsets.UTF_8);
                when(getResult.sourceRef()).thenReturn(new BytesArray(bytes, 0, bytes.length));
                when(getResult.sourceAsString()).thenReturn(sourceJson);
            }
            l.onResponse(new GetResponse(getResult));
            return null;
        }).when(client).get(any(GetRequest.class), any());
    }

    private void stubUpdateSucceeds() {
        // The update paths use the fluent client.prepareUpdate(idx,id).setRefreshPolicy(..).setDoc(..).request()
        // builder; RETURNS_SELF makes every builder call return the same mock, and request() yields a mock request.
        UpdateRequestBuilder builder = mock(UpdateRequestBuilder.class, org.mockito.Answers.RETURNS_SELF);
        when(builder.request()).thenReturn(mock(UpdateRequest.class));
        when(client.prepareUpdate(anyString(), anyString())).thenReturn(builder);
        doAnswer(inv -> {
            ActionListener<UpdateResponse> l = inv.getArgument(1);
            l.onResponse(mock(UpdateResponse.class));
            return null;
        }).when(client).update(any(UpdateRequest.class), any());
    }

    // ---------- fetchSharingInfoForIds -------------------------------------------------------------

    @Test
    public void fetchSharingInfoForIds_returnsEmptyForBlankIndexOrNoIds() {
        AtomicReference<Map<String, ResourceSharing>> out = new AtomicReference<>();
        handler.fetchSharingInfoForIds(RESOURCE_INDEX, List.of(), ActionListener.wrap(out::set, e -> {}));
        assertTrue(out.get().isEmpty());

        out.set(null);
        handler.fetchSharingInfoForIds("  ", List.of("a"), ActionListener.wrap(out::set, e -> {}));
        assertTrue(out.get().isEmpty());

        // no client call should have been issued
        verify(client, never()).multiGet(any(), any());
    }

    @Test
    public void fetchSharingInfoForIds_parsesExistingAndSkipsMissing() {
        doAnswer(inv -> {
            ActionListener<MultiGetResponse> l = inv.getArgument(1);
            MultiGetItemResponse exists = existingItem("res-1", "{\"resource_id\":\"res-1\",\"created_by\":{\"user\":\"alice\"}}");
            GetResult missingResult = mock(GetResult.class);
            when(missingResult.getId()).thenReturn("res-2");
            when(missingResult.isExists()).thenReturn(false);
            MultiGetItemResponse missing = new MultiGetItemResponse(new GetResponse(missingResult), null);
            l.onResponse(new MultiGetResponse(new MultiGetItemResponse[] { exists, missing }));
            return null;
        }).when(client).multiGet(any(MultiGetRequest.class), any());

        AtomicReference<Map<String, ResourceSharing>> out = new AtomicReference<>();
        handler.fetchSharingInfoForIds(RESOURCE_INDEX, List.of("res-1", "res-2"), ActionListener.wrap(out::set, e -> {}));

        assertEquals(1, out.get().size());
        assertTrue(out.get().containsKey("res-1"));
        assertEquals("alice", out.get().get("res-1").getCreatedBy().getUsername());
    }

    // ---------- backfillWorkspacesOnExisting -------------------------------------------------------

    @Test
    public void backfill_noopForEmptyWorkspaces() {
        AtomicReference<Boolean> out = new AtomicReference<>();
        handler.backfillWorkspacesOnExisting(RESOURCE_INDEX, "res-1", Set.of(), ActionListener.wrap(out::set, e -> {}));
        assertFalse(out.get());
        verify(client, never()).get(any(), any());
        verify(client, never()).update(any(), any());
    }

    @Test
    public void backfill_noopWhenRecordMissing() {
        stubGet("res-1", false, null);
        AtomicReference<Boolean> out = new AtomicReference<>();
        handler.backfillWorkspacesOnExisting(RESOURCE_INDEX, "res-1", Set.of("ws-a"), ActionListener.wrap(out::set, e -> {}));
        assertFalse(out.get());
        verify(client, never()).update(any(), any());
    }

    @Test
    public void backfill_noopWhenWorkspacesAlreadyPresent() {
        stubGet("res-1", true, "{\"resource_id\":\"res-1\",\"created_by\":{\"user\":\"alice\"},\"workspaces\":[\"ws-a\",\"ws-b\"]}");
        AtomicReference<Boolean> out = new AtomicReference<>();
        handler.backfillWorkspacesOnExisting(RESOURCE_INDEX, "res-1", Set.of("ws-a"), ActionListener.wrap(out::set, e -> {}));
        assertFalse(out.get());
        // nothing new to add -> no write
        verify(client, never()).update(any(), any());
    }

    @Test
    public void backfill_mergesAndUpdatesWhenNewWorkspaces() {
        stubGet("res-1", true, "{\"resource_id\":\"res-1\",\"created_by\":{\"user\":\"alice\"}}");
        stubUpdateSucceeds();

        AtomicReference<Boolean> out = new AtomicReference<>();
        handler.backfillWorkspacesOnExisting(RESOURCE_INDEX, "res-1", Set.of("ws-a", "ws-b"), ActionListener.wrap(out::set, e -> {}));

        assertTrue(out.get());
        // two updates: one to persist workspaces on the sharing record, one to refresh all_shared_principals
        verify(client, times(2)).update(any(UpdateRequest.class), any());
    }
}
