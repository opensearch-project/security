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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexRequestBuilder;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateRequestBuilder;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.index.Index;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.index.get.GetResult;
import org.opensearch.security.resources.sharing.Recipient;
import org.opensearch.security.resources.sharing.Recipients;
import org.opensearch.security.resources.sharing.ResourceSharing;
import org.opensearch.security.resources.sharing.ShareWith;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import org.mockito.ArgumentCaptor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the workspace-related read/write helpers on {@link ResourceSharingIndexHandler}:
 * {@link ResourceSharingIndexHandler#fetchSharingInfoForIds} and
 * {@link ResourceSharingIndexHandler#reconcileWorkspaces}.
 */
public class ResourceSharingIndexHandlerTests {

    private static final String RESOURCE_INDEX = "test-index";

    private Client client;
    private ThreadPool threadPool;
    private ResourceSharingIndexHandler handler;

    @Before
    public void setUp() {
        client = mock(Client.class);
        threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));
        handler = new ResourceSharingIndexHandler(client, threadPool, mock(ResourcePluginInfo.class));
    }

    // reconcileWorkspaces reads the sharing record's raw source (workspaces + workspaces_seq_no) and its
    // seq_no/primary_term for the optimistic-concurrency guard; stub client.get to return the record.
    private void stubRecordGet(boolean exists, String recordJson) {
        doAnswer(inv -> {
            ActionListener<GetResponse> l = inv.getArgument(1);
            GetResult getResult = mock(GetResult.class);
            when(getResult.getId()).thenReturn("res-1");
            when(getResult.isExists()).thenReturn(exists);
            if (exists) {
                byte[] bytes = recordJson.getBytes(StandardCharsets.UTF_8);
                BytesArray source = new BytesArray(bytes, 0, bytes.length);
                when(getResult.sourceRef()).thenReturn(source);
                when(getResult.sourceAsString()).thenReturn(recordJson);
                when(getResult.sourceAsMap()).thenReturn(XContentHelper.convertToMap(source, false, XContentType.JSON).v2());
                when(getResult.getSeqNo()).thenReturn(1L);
                when(getResult.getPrimaryTerm()).thenReturn(1L);
            }
            l.onResponse(new GetResponse(getResult));
            return null;
        }).when(client).get(any(GetRequest.class), any());
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

    // ---------- reconcileWorkspaces ----------------------------------------------------------------

    @Test
    public void reconcile_appliesWhenNewerSeqNo() {
        // No prior guard on the record (workspaces_seq_no absent) -> any source seq_no applies.
        stubRecordGet(true, "{\"resource_id\":\"res-1\",\"created_by\":{\"user\":\"alice\"}}");
        stubUpdateSucceeds();

        AtomicReference<Boolean> out = new AtomicReference<>();
        handler.reconcileWorkspaces(RESOURCE_INDEX, "res-1", Set.of("ws-a", "ws-b"), 5L, ActionListener.wrap(out::set, e -> {}));

        assertTrue(out.get());
        verify(client, times(1)).update(any(UpdateRequest.class), any());
    }

    @Test
    public void reconcile_removesWhenDissociated() {
        stubRecordGet(
            true,
            "{\"resource_id\":\"res-1\",\"created_by\":{\"user\":\"alice\"},\"workspaces\":[\"ws-a\",\"ws-b\"],\"workspaces_seq_no\":1}"
        );
        stubUpdateSucceeds();

        AtomicReference<Boolean> out = new AtomicReference<>();
        handler.reconcileWorkspaces(RESOURCE_INDEX, "res-1", Set.of("ws-a"), 5L, ActionListener.wrap(out::set, e -> {}));

        assertTrue(out.get());
        verify(client, times(1)).update(any(UpdateRequest.class), any());
    }

    @Test
    public void reconcile_clearsWhenTargetEmpty() {
        stubRecordGet(
            true,
            "{\"resource_id\":\"res-1\",\"created_by\":{\"user\":\"alice\"},\"workspaces\":[\"ws-a\"],\"workspaces_seq_no\":1}"
        );
        stubUpdateSucceeds();

        AtomicReference<Boolean> out = new AtomicReference<>();
        handler.reconcileWorkspaces(RESOURCE_INDEX, "res-1", Set.of(), 5L, ActionListener.wrap(out::set, e -> {}));

        assertTrue(out.get());
        verify(client, times(1)).update(any(UpdateRequest.class), any());
    }

    @Test
    public void reconcile_rejectsStaleSeqNo() {
        // Monotonic guard: a reconcile older than the last-applied source seq_no must not overwrite newer state.
        stubRecordGet(
            true,
            "{\"resource_id\":\"res-1\",\"created_by\":{\"user\":\"alice\"},\"workspaces\":[\"ws-a\"],\"workspaces_seq_no\":5}"
        );

        AtomicReference<Boolean> out = new AtomicReference<>();
        handler.reconcileWorkspaces(RESOURCE_INDEX, "res-1", Set.of(), 3L, ActionListener.wrap(out::set, e -> {}));

        assertFalse(out.get());
        verify(client, never()).update(any(), any());
    }

    @Test
    public void reconcile_advancesGuardWhenContentUnchanged() {
        // Content already matches, but a newer seq_no still advances the guard so a later stale reconcile is gated.
        stubRecordGet(
            true,
            "{\"resource_id\":\"res-1\",\"created_by\":{\"user\":\"alice\"},\"workspaces\":[\"ws-a\"],\"workspaces_seq_no\":1}"
        );
        stubUpdateSucceeds();

        AtomicReference<Boolean> out = new AtomicReference<>();
        handler.reconcileWorkspaces(RESOURCE_INDEX, "res-1", Set.of("ws-a"), 5L, ActionListener.wrap(out::set, e -> {}));

        assertFalse(out.get()); // content unchanged
        verify(client, times(1)).update(any(UpdateRequest.class), any()); // but the guard was advanced
    }

    @Test
    public void reconcile_retriesWhenRecordMissing() {
        // The record is created asynchronously; a reconcile that finds it missing must schedule a retry rather than
        // treat it as synced. (threadPool.schedule is a no-op mock here, so the retry itself does not fire.)
        stubRecordGet(false, null);

        handler.reconcileWorkspaces(RESOURCE_INDEX, "res-1", Set.of("ws-a"), 5L, ActionListener.wrap(b -> {}, e -> {}));

        verify(threadPool).schedule(any(Runnable.class), any(TimeValue.class), anyString());
        verify(client, never()).update(any(), any());
    }

    @Test
    public void share_reappliesToLatestRecordOnVersionConflict() {
        // Interleave: share fetches a stale snapshot ([ws-a], guard 10); before it writes, a reconcile has moved the
        // record to []/guard 11 (simulated by a version conflict on the first optimistic-concurrency write). share
        // MUST re-fetch the newer record and re-apply share_with to it, so the newer (empty) workspaces and guard 11
        // survive rather than being reverted to [ws-a]/10.
        AtomicInteger getCount = new AtomicInteger();
        doAnswer(inv -> {
            ActionListener<GetResponse> l = inv.getArgument(1);
            boolean first = getCount.getAndIncrement() == 0;
            String json = first
                ? "{\"resource_id\":\"res-1\",\"resource_type\":\"s\",\"created_by\":{\"user\":\"owner\"},\"workspaces\":[\"ws-a\"],\"workspaces_seq_no\":10}"
                : "{\"resource_id\":\"res-1\",\"resource_type\":\"s\",\"created_by\":{\"user\":\"owner\"},\"workspaces_seq_no\":11}";
            GetResult gr = mock(GetResult.class);
            when(gr.getId()).thenReturn("res-1");
            when(gr.isExists()).thenReturn(true);
            when(gr.sourceAsString()).thenReturn(json);
            when(gr.getSeqNo()).thenReturn(first ? 10L : 11L);
            when(gr.getPrimaryTerm()).thenReturn(1L);
            l.onResponse(new GetResponse(gr));
            return null;
        }).when(client).get(any(GetRequest.class), any());

        IndexRequestBuilder indexBuilder = mock(IndexRequestBuilder.class, org.mockito.Answers.RETURNS_SELF);
        when(indexBuilder.request()).thenReturn(mock(IndexRequest.class));
        when(client.prepareIndex(anyString())).thenReturn(indexBuilder);
        AtomicInteger indexCount = new AtomicInteger();
        doAnswer(inv -> {
            ActionListener<IndexResponse> l = inv.getArgument(1);
            if (indexCount.getAndIncrement() == 0) {
                // First write loses to a concurrent reconcile.
                l.onFailure(new VersionConflictEngineException(new ShardId(new Index("i", "u"), 0), "res-1", "conflict"));
            } else {
                l.onResponse(mock(IndexResponse.class));
            }
            return null;
        }).when(client).index(any(IndexRequest.class), any());
        stubUpdateSucceeds(); // updateResourceVisibility on success

        ShareWith shareWith = new ShareWith(Map.of("read", new Recipients(Map.of(Recipient.USERS, Set.of("bob")))));
        AtomicReference<ResourceSharing> out = new AtomicReference<>();
        handler.share("res-1", RESOURCE_INDEX, shareWith, ActionListener.wrap(out::set, e -> {}));

        verify(client, times(2)).get(any(GetRequest.class), any());   // re-fetched the latest on conflict
        verify(client, times(2)).index(any(IndexRequest.class), any());

        // Each write's optimistic-concurrency guard came from the record fetched that attempt (stale 10, then 11).
        verify(indexBuilder).setIfSeqNo(10L);
        verify(indexBuilder).setIfSeqNo(11L);
        verify(indexBuilder, times(2)).setIfPrimaryTerm(1L);

        ArgumentCaptor<XContentBuilder> src = ArgumentCaptor.forClass(XContentBuilder.class);
        verify(indexBuilder, atLeast(2)).setSource(src.capture());
        String latest = src.getAllValues().get(src.getAllValues().size() - 1).toString();
        assertFalse("stale workspace must not be re-applied over the newer state", latest.contains("ws-a"));
        assertTrue("newer guard must be preserved", latest.contains("\"workspaces_seq_no\":11"));
        assertTrue("share_with recipient must be reapplied to the latest record", latest.contains("bob"));

        // The share completed successfully after the retry.
        assertNotNull(out.get());
    }
}
