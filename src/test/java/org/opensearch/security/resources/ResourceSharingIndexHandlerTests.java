/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexRequestBuilder;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateRequestBuilder;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.AbstractRunnable;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.concurrency.OpenSearchRejectedExecutionException;
import org.opensearch.core.index.Index;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.engine.DocumentMissingException;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.index.get.GetResult;
import org.opensearch.security.resources.sharing.CreatedBy;
import org.opensearch.security.resources.sharing.Recipient;
import org.opensearch.security.resources.sharing.Recipients;
import org.opensearch.security.resources.sharing.ResourceSharing;
import org.opensearch.security.resources.sharing.ShareWith;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static org.opensearch.security.resources.ResourceSharingIndexHandler.getSharingIndex;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
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
@SuppressWarnings("unchecked") // action listener mocks
public class ResourceSharingIndexHandlerTests {

    private static final String RESOURCE_INDEX = "test-index";
    private static final long RESOURCE_DOC_SEQ_NO = 7L;

    private Client client;
    private IndicesAdminClient indicesAdminClient;
    private ThreadPool threadPool;
    private ResourceSharingIndexHandler handler;
    // The resource document's current version, as the stubbed engine sees it
    private final AtomicLong resourceSeqNo = new AtomicLong(RESOURCE_DOC_SEQ_NO);

    @Before
    public void setUp() {
        client = mock(Client.class);
        AdminClient adminClient = mock(AdminClient.class);
        indicesAdminClient = mock(IndicesAdminClient.class);
        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        stubSharingIndexExists(true);
        threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));
        handler = new ResourceSharingIndexHandler(client, threadPool, mock(ResourcePluginInfo.class));
    }

    private void stubSharingIndexExists(boolean exists) {
        doAnswer(inv -> {
            ActionListener<IndicesExistsResponse> l = inv.getArgument(1);
            l.onResponse(new IndicesExistsResponse(exists));
            return null;
        }).when(indicesAdminClient).exists(any(IndicesExistsRequest.class), any());
    }

    private void stubSharingIndexCreate(Consumer<ActionListener<CreateIndexResponse>> outcome) {
        doAnswer(inv -> {
            outcome.accept(inv.getArgument(1));
            return null;
        }).when(indicesAdminClient).create(any(CreateIndexRequest.class), any());
    }

    private void stubGetFails(Exception failure) {
        doAnswer(inv -> {
            ActionListener<GetResponse> l = inv.getArgument(1);
            l.onFailure(failure);
            return null;
        }).when(client).get(any(GetRequest.class), any());
    }

    private void stubSearchFails(Exception failure) {
        doAnswer(inv -> {
            ActionListener<SearchResponse> l = inv.getArgument(1);
            l.onFailure(failure);
            return null;
        }).when(client).search(any(SearchRequest.class), any());
    }

    private void stubDeleteFails(Exception failure) {
        doAnswer(inv -> {
            ActionListener<DeleteResponse> l = inv.getArgument(1);
            l.onFailure(failure);
            return null;
        }).when(client).delete(any(DeleteRequest.class), any());
    }

    private static IndexNotFoundException sharingIndexMissing() {
        return new IndexNotFoundException(getSharingIndex(RESOURCE_INDEX));
    }

    // reconcileWorkspaces reads the sharing record's raw source (workspaces + workspaces_seq_no) and its
    // seq_no/primary_term for the optimistic-concurrency guard; stub client.get to return the record.
    private void stubRecordGet(boolean exists, String recordJson) {
        doAnswer(inv -> {
            ActionListener<GetResponse> l = inv.getArgument(1);
            l.onResponse(new GetResponse(exists ? getResult(recordJson, 1L) : missingResult()));
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
        stubUpdate(l -> l.onResponse(mock(UpdateResponse.class)));
    }

    private void stubUpdate(Consumer<ActionListener<UpdateResponse>> outcome) {
        // The update paths use the fluent client.prepareUpdate(idx,id).setRefreshPolicy(..).setDoc(..).request()
        // builder; RETURNS_SELF makes every builder call return the same mock, and request() yields a mock request.
        stubUpdateBuilder();
        doAnswer(inv -> {
            outcome.accept(inv.getArgument(1));
            return null;
        }).when(client).update(any(UpdateRequest.class), any());
    }

    private void stubIndexSucceeds() {
        stubRecordIndexSucceeds();
    }

    private void stubUpdateFails() {
        stubUpdate(l -> l.onFailure(new IllegalStateException("visibility write rejected")));
    }

    // ---------- visibility update failures --------------------------------------------------------

    /** Asserts the listener failed because of the visibility write, not because an earlier step failed. */
    private static void assertVisibilityWriteFailure(ActionListener<?> listener) {
        ArgumentCaptor<Exception> failure = ArgumentCaptor.forClass(Exception.class);
        verify(listener).onFailure(failure.capture());
        assertTrue(failure.getValue() instanceof OpenSearchStatusException);
        assertEquals("visibility write rejected", failure.getValue().getCause().getMessage());
    }

    @Test
    public void shareReportsAFailedVisibilityUpdate() {
        stubRecordGet(true, "{\"resource_id\":\"res-1\",\"created_by\":{\"user\":\"alice\"}}");
        stubIndexSucceeds();
        stubUpdateFails();

        ActionListener<ResourceSharing> listener = mock(ActionListener.class);
        handler.share(
            "res-1",
            RESOURCE_INDEX,
            new ShareWith(Map.of("read_only", new Recipients(Map.of(Recipient.USERS, Set.of("bob"))))),
            listener
        );

        // The record was written but the field it projects to was not, so the caller must not see success
        verify(listener, never()).onResponse(any());
        verify(client).index(any(IndexRequest.class), any());
        assertVisibilityWriteFailure(listener);
    }

    @Test
    public void createReportsAFailedVisibilityUpdate() throws Exception {
        stubRecordGet(true, "{\"resource_id\":\"res-1\",\"created_by\":{\"user\":\"alice\"}}");
        stubIndexSucceeds();
        stubUpdateFails();

        ActionListener<ResourceSharing> listener = mock(ActionListener.class);
        handler.indexResourceSharing(
            RESOURCE_INDEX,
            ResourceSharing.builder().resourceId("res-1").resourceType("test").createdBy(new CreatedBy("alice")).build(),
            listener
        );

        verify(listener, never()).onResponse(any());
        verify(client).index(any(IndexRequest.class), any());
        assertVisibilityWriteFailure(listener);
    }

    @Test
    public void restoreReportsAFailedVisibilityUpdate() {
        stubRecordGet(true, "{\"resource_id\":\"res-1\",\"created_by\":{\"user\":\"alice\"}}");
        stubUpdateFails();

        ActionListener<Void> listener = mock(ActionListener.class);
        handler.fetchAndUpdateResourceVisibility("res-1", RESOURCE_INDEX, listener);

        verify(listener, never()).onResponse(any());
        assertVisibilityWriteFailure(listener);
    }

    // ---------- sharing index created by the first record -----------------------------------------

    @Test
    public void create_writesTheRecordWithoutCreatingAnExistingSharingIndex() throws Exception {
        stubRecordIndexSucceeds();

        handler.indexResourceSharing(RESOURCE_INDEX, newRecord(), ActionListener.wrap(r -> {}, e -> {}));

        verify(indicesAdminClient, never()).create(any(CreateIndexRequest.class), any());
        verify(client).index(any(IndexRequest.class), any());
    }

    @Test
    public void create_createsTheSharingIndexBeforeTheFirstRecord() throws Exception {
        stubSharingIndexExists(false);
        stubSharingIndexCreate(l -> l.onResponse(mock(CreateIndexResponse.class)));
        stubRecordIndexSucceeds();

        handler.indexResourceSharing(RESOURCE_INDEX, newRecord(), ActionListener.wrap(r -> {}, e -> {}));

        ArgumentCaptor<CreateIndexRequest> created = ArgumentCaptor.forClass(CreateIndexRequest.class);
        InOrder order = inOrder(indicesAdminClient, client);
        order.verify(indicesAdminClient).create(created.capture(), any());
        order.verify(client).index(any(IndexRequest.class), any());
        assertEquals(getSharingIndex(RESOURCE_INDEX), created.getValue().index());
        assertEquals("1", created.getValue().settings().get("index.number_of_shards"));
        assertEquals("true", created.getValue().settings().get("index.hidden"));
    }

    @Test
    public void create_writesTheRecordWhenTheSharingIndexWasCreatedConcurrently() throws Exception {
        stubSharingIndexExists(false);
        stubSharingIndexCreate(l -> l.onFailure(new ResourceAlreadyExistsException("index [{}] already exists", RESOURCE_INDEX)));
        stubRecordIndexSucceeds();

        handler.indexResourceSharing(RESOURCE_INDEX, newRecord(), ActionListener.wrap(r -> {}, e -> {}));

        verify(client).index(any(IndexRequest.class), any());
    }

    @Test
    public void create_reportsAFailureToCreateTheSharingIndex() throws Exception {
        stubSharingIndexExists(false);
        Exception failure = new OpenSearchStatusException("cluster manager not discovered", RestStatus.SERVICE_UNAVAILABLE);
        stubSharingIndexCreate(l -> l.onFailure(failure));
        stubRecordIndexSucceeds();

        List<Exception> failures = new ArrayList<>();
        handler.indexResourceSharing(RESOURCE_INDEX, newRecord(), ActionListener.wrap(r -> fail("must not succeed"), failures::add));

        assertEquals(List.of(failure), failures);
        verify(client, never()).index(any(IndexRequest.class), any());
    }

    @Test
    public void create_reportsAFailedSharingIndexExistenceCheck() throws Exception {
        Exception failure = new OpenSearchStatusException("node closed", RestStatus.SERVICE_UNAVAILABLE);
        doAnswer(inv -> {
            ActionListener<IndicesExistsResponse> l = inv.getArgument(1);
            l.onFailure(failure);
            return null;
        }).when(indicesAdminClient).exists(any(IndicesExistsRequest.class), any());
        stubRecordIndexSucceeds();

        List<Exception> failures = new ArrayList<>();
        handler.indexResourceSharing(RESOURCE_INDEX, newRecord(), ActionListener.wrap(r -> fail("must not succeed"), failures::add));

        assertEquals(List.of(failure), failures);
        verify(indicesAdminClient, never()).create(any(CreateIndexRequest.class), any());
        verify(client, never()).index(any(IndexRequest.class), any());
    }

    // ---------- reads before the sharing index exists ----------------------------------------------

    @Test
    public void fetchSharingInfo_findsNoRecordWhenTheSharingIndexIsMissing() {
        stubGetFails(sharingIndexMissing());

        List<ResourceSharing> responses = new ArrayList<>();
        handler.fetchSharingInfo(RESOURCE_INDEX, "res-1", ActionListener.wrap(responses::add, e -> fail(e.toString())));

        assertEquals(1, responses.size());
        assertNull(responses.get(0));
    }

    @Test
    public void fetchSharingInfo_reportsOtherReadFailuresAsAnInternalError() {
        stubGetFails(new OpenSearchStatusException("node closed", RestStatus.SERVICE_UNAVAILABLE));

        List<Exception> failures = new ArrayList<>();
        handler.fetchSharingInfo(RESOURCE_INDEX, "res-1", ActionListener.wrap(r -> fail("must not succeed"), failures::add));

        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, ((OpenSearchStatusException) failures.get(0)).status());
    }

    @Test
    public void share_findsNoRecordWhenTheSharingIndexIsMissing() {
        stubGetFails(sharingIndexMissing());

        List<ResourceSharing> responses = new ArrayList<>();
        handler.share("res-1", RESOURCE_INDEX, shareWith("alice"), ActionListener.wrap(responses::add, e -> fail(e.toString())));

        assertEquals(1, responses.size());
        assertNull(responses.get(0));
        verify(client, never()).index(any(IndexRequest.class), any());
    }

    @Test
    public void share_reportsOtherFailuresToReadTheRecord() {
        Exception failure = new OpenSearchStatusException("node closed", RestStatus.SERVICE_UNAVAILABLE);
        stubGetFails(failure);

        List<Exception> failures = new ArrayList<>();
        handler.share("res-1", RESOURCE_INDEX, shareWith("alice"), ActionListener.wrap(r -> fail("must not succeed"), failures::add));

        assertEquals(List.of(failure), failures);
    }

    @Test
    public void deleteResourceSharingRecord_findsNothingToDeleteWhenTheSharingIndexIsMissing() {
        stubDeleteFails(sharingIndexMissing());

        List<Boolean> responses = new ArrayList<>();
        handler.deleteResourceSharingRecord("res-1", RESOURCE_INDEX, ActionListener.wrap(responses::add, e -> fail(e.toString())));

        assertEquals(List.of(false), responses);
    }

    @Test
    public void deleteResourceSharingRecord_reportsOtherFailures() {
        Exception failure = new OpenSearchStatusException("node closed", RestStatus.SERVICE_UNAVAILABLE);
        stubDeleteFails(failure);

        List<Exception> failures = new ArrayList<>();
        handler.deleteResourceSharingRecord("res-1", RESOURCE_INDEX, ActionListener.wrap(r -> fail("must not succeed"), failures::add));

        assertEquals(List.of(failure), failures);
    }

    @Test
    public void fetchAllResourceIds_findsNoneWhenTheSharingIndexIsMissing() {
        stubSearchFails(sharingIndexMissing());

        List<Set<String>> responses = new ArrayList<>();
        handler.fetchAllResourceIds(RESOURCE_INDEX, ActionListener.wrap(responses::add, e -> fail(e.toString())));

        assertEquals(List.of(Set.of()), responses);
    }

    @Test
    public void fetchAllResourceIds_reportsOtherSearchFailures() {
        Exception failure = new OpenSearchStatusException("node closed", RestStatus.SERVICE_UNAVAILABLE);
        stubSearchFails(failure);

        List<Exception> failures = new ArrayList<>();
        handler.fetchAllResourceIds(RESOURCE_INDEX, ActionListener.wrap(r -> fail("must not succeed"), failures::add));

        assertEquals(List.of(failure), failures);
    }

    @Test
    public void fetchAllResourceSharingRecords_findsNoneWhenTheSharingIndexIsMissing() {
        stubSearchFails(sharingIndexMissing());

        List<Set<SharingRecord>> responses = new ArrayList<>();
        handler.fetchAllResourceSharingRecords(RESOURCE_INDEX, "test", ActionListener.wrap(responses::add, e -> fail(e.toString())));

        assertEquals(List.of(Set.of()), responses);
    }

    @Test
    public void fetchAllResourceSharingRecords_reportsOtherSearchFailures() {
        Exception failure = new OpenSearchStatusException("node closed", RestStatus.SERVICE_UNAVAILABLE);
        stubSearchFails(failure);

        List<Exception> failures = new ArrayList<>();
        handler.fetchAllResourceSharingRecords(RESOURCE_INDEX, "test", ActionListener.wrap(r -> fail("must not succeed"), failures::add));

        assertEquals(List.of(failure), failures);
    }

    @Test
    public void reconcile_retriesWhenTheSharingIndexIsMissing() {
        // The sharing index is created with the first record, so a reconcile can arrive before either exists
        stubGetFails(sharingIndexMissing());

        handler.reconcileWorkspaces(RESOURCE_INDEX, "res-1", Set.of("ws-a"), 5L, ActionListener.wrap(b -> {}, e -> fail(e.toString())));

        verify(threadPool).schedule(any(Runnable.class), any(TimeValue.class), anyString());
        verify(client, never()).update(any(), any());
    }

    @Test
    public void reconcile_givesUpWhenTheSharingIndexStaysMissing() {
        stubGetFails(sharingIndexMissing());
        doAnswer(inv -> {
            ((Runnable) inv.getArgument(0)).run();
            return null;
        }).when(threadPool).schedule(any(Runnable.class), any(TimeValue.class), anyString());

        List<Boolean> responses = new ArrayList<>();
        handler.reconcileWorkspaces(
            RESOURCE_INDEX,
            "res-1",
            Set.of("ws-a"),
            5L,
            ActionListener.wrap(responses::add, e -> fail(e.toString()))
        );

        assertEquals(List.of(false), responses);
        verify(client, times(5)).get(any(GetRequest.class), any());
    }

    @Test
    public void reconcile_reportsOtherFailuresToReadTheRecord() {
        Exception failure = new OpenSearchStatusException("node closed", RestStatus.SERVICE_UNAVAILABLE);
        stubGetFails(failure);

        List<Exception> failures = new ArrayList<>();
        handler.reconcileWorkspaces(
            RESOURCE_INDEX,
            "res-1",
            Set.of("ws-a"),
            5L,
            ActionListener.wrap(b -> fail("must not succeed"), failures::add)
        );

        assertEquals(List.of(failure), failures);
        verify(threadPool, never()).schedule(any(Runnable.class), any(TimeValue.class), anyString());
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

        IndexRequestBuilder indexBuilder = mock(IndexRequestBuilder.class, Answers.RETURNS_SELF);
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
        stubUpdateSucceeds(); // the visibility sync after the record write

        ShareWith shareWith = new ShareWith(Map.of("read", new Recipients(Map.of(Recipient.USERS, Set.of("bob")))));
        AtomicReference<ResourceSharing> out = new AtomicReference<>();
        handler.share("res-1", RESOURCE_INDEX, shareWith, ActionListener.wrap(out::set, e -> {}));

        // Two record reads by the share (the second after the conflict) and one by the visibility sync that follows
        verify(client, times(3)).get(argThat(r -> r != null && r.index().equals(getSharingIndex(RESOURCE_INDEX))), any());
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

    // ---------- all_shared_principals stays in step with the record ---------------------------------

    @Test
    public void share_guardsTheVisibilityWriteWithTheResourceDocumentVersion() {
        stubSharingAndResource(() -> recordJson(List.of()));
        stubRecordIndexSucceeds();
        UpdateRequestBuilder builder = stubUpdateBuilder();
        stubUpdates(builder, versioned -> {});

        AtomicReference<ResourceSharing> shared = new AtomicReference<>();
        handler.share("res-1", RESOURCE_INDEX, shareWith("alice"), ActionListener.wrap(shared::set, e -> {}));

        assertNotNull("the share must complete", shared.get());
        verify(builder).setIfSeqNo(RESOURCE_DOC_SEQ_NO);
        verify(builder).setIfPrimaryTerm(1L);
    }

    /**
     * A competing field write that lands between this write's version read and record read must not let the older record's
     * value land: the version has moved, so this write conflicts and retries against the newer record.
     */
    @Test
    public void share_rejectsAVisibilityValueDerivedFromAnOlderRecord() throws Exception {
        runScheduledTasksInline();
        final String staleRecord = recordJson(List.of("alice"));
        final String freshRecord = recordJson(List.of("alice", "bob", "carol"));

        AtomicInteger recordReads = new AtomicInteger();
        // Read 0 is the share's; read 1 is the sync's, during which a competing field write lands
        stubSharingAndResource(() -> {
            int n = recordReads.getAndIncrement();
            if (n == 1) resourceSeqNo.incrementAndGet();
            return n <= 1 ? staleRecord : freshRecord;
        });
        stubRecordIndexSucceeds();
        UpdateRequestBuilder builder = stubUpdateBuilder();
        List<List<String>> landed = new ArrayList<>();
        stubUpdates(builder, landed::add);

        AtomicReference<ResourceSharing> shared = new AtomicReference<>();
        handler.share("res-1", RESOURCE_INDEX, shareWith("bob"), ActionListener.wrap(shared::set, e -> {}));

        assertNotNull("the share must complete", shared.get());
        assertEquals("exactly one write may land", 1, landed.size());
        assertEquals(
            "the value that landed must be derived from the newer record",
            Set.copyOf(principalsOf(freshRecord)),
            Set.copyOf(landed.get(0))
        );
    }

    /**
     * A revoke writes the record first and the field after it, and the field it writes drops the revoked principal.
     */
    @Test
    public void revoke_writesTheRecordThenTheFieldWithoutTheRevokedPrincipal() {
        AtomicInteger recordReads = new AtomicInteger();
        stubSharingAndResource(
            () -> recordReads.getAndIncrement() == 0 ? recordJson(List.of("alice", "bob")) : recordJson(List.of("alice"))
        );
        List<String> order = new ArrayList<>();
        stubRecordIndexSucceeds(() -> order.add("record"));
        UpdateRequestBuilder builder = stubUpdateBuilder();
        List<List<String>> landed = new ArrayList<>();
        stubUpdates(builder, value -> {
            order.add("visibility");
            landed.add(value);
        });

        AtomicReference<ResourceSharing> revoked = new AtomicReference<>();
        handler.patchSharingInfo(
            "res-1",
            RESOURCE_INDEX,
            null,
            new ShareWith(Map.of("read_only", new Recipients(Map.of(Recipient.USERS, Set.of("bob"))))),
            false,
            null,
            ActionListener.wrap(revoked::set, e -> {})
        );

        assertNotNull("the revoke must complete", revoked.get());
        assertEquals(List.of("record", "visibility"), order);
        assertFalse(landed.get(0).contains("user:bob"));
        assertTrue(landed.get(0).contains("user:alice"));
    }

    @Test
    public void share_failsOnceVisibilityRetriesAreExhausted() {
        runScheduledTasksInline();
        stubSharingAndResource(() -> recordJson(List.of()));
        stubRecordIndexSucceeds();
        stubUpdateBuilder();
        AtomicInteger updates = new AtomicInteger();
        stubUpdateFails(() -> {
            updates.incrementAndGet();
            return versionConflict();
        });

        List<Exception> failures = new ArrayList<>();
        handler.share("res-1", RESOURCE_INDEX, shareWith("alice"), ActionListener.wrap(r -> {}, failures::add));

        assertEquals("the retry is bounded", 5, updates.get());
        assertEquals(1, failures.size());
        assertTrue(failures.get(0).getMessage().contains("repeating the request re-applies it"));
    }

    @Test
    public void share_reportsAFailureToWriteVisibility() {
        stubSharingAndResource(() -> recordJson(List.of()));
        stubRecordIndexSucceeds();
        stubUpdateBuilder();
        stubUpdateFails(() -> new OpenSearchStatusException("mapping rejected the field", RestStatus.BAD_REQUEST));

        AtomicReference<ResourceSharing> allowed = new AtomicReference<>();
        List<Exception> failures = new ArrayList<>();
        handler.share("res-1", RESOURCE_INDEX, shareWith("alice"), ActionListener.wrap(allowed::set, failures::add));

        assertNull("the share must not report success when the field was not written", allowed.get());
        assertEquals(1, failures.size());
        assertTrue(failures.get(0).getMessage().contains("repeating the request re-applies it"));
    }

    @Test
    public void share_passesThroughAMissingResourceDocument() {
        stubGets(ResourceSharingIndexHandlerTests::missingResult, () -> getResult(recordJson(List.of()), 1L));
        stubRecordIndexSucceeds();

        List<Exception> failures = new ArrayList<>();
        handler.share("res-1", RESOURCE_INDEX, shareWith("alice"), ActionListener.wrap(r -> {}, failures::add));

        assertEquals(1, failures.size());
        assertTrue(failures.get(0) instanceof ResourceNotFoundException);
    }

    @Test
    public void share_failsWhenTheRecordDisappearsBeforeVisibilityIsWritten() {
        AtomicInteger recordReads = new AtomicInteger();
        // The share reads the record; by the time the sync reads it, it is gone
        stubGets(this::resourceDoc, () -> recordReads.getAndIncrement() == 0 ? getResult(recordJson(List.of()), 1L) : missingResult());
        stubRecordIndexSucceeds();

        List<Exception> failures = new ArrayList<>();
        handler.share("res-1", RESOURCE_INDEX, shareWith("alice"), ActionListener.wrap(r -> {}, failures::add));

        assertEquals(1, failures.size());
        assertTrue(failures.get(0).getMessage().contains("Failed to update which principals"));
    }

    /**
     * A create cannot be repeated, so its failure says how the field is restored instead of asking for a retry.
     */
    @Test
    public void create_reportsAFailureToWriteVisibilityWithoutAskingForARetry() throws Exception {
        stubSharingAndResource(() -> recordJson(List.of()));
        stubRecordIndexSucceeds();
        stubUpdateBuilder();
        stubUpdateFails(() -> new OpenSearchStatusException("mapping rejected the field", RestStatus.BAD_REQUEST));

        ResourceSharing created = newRecord();
        List<Exception> failures = new ArrayList<>();
        handler.indexResourceSharing(RESOURCE_INDEX, created, ActionListener.wrap(r -> {}, failures::add));

        assertEquals(1, failures.size());
        assertFalse(failures.get(0).getMessage().contains("repeating the request re-applies it"));
        assertTrue(failures.get(0).getMessage().contains("restored on the next update"));
    }

    /**
     * A retry the executor rejects, as it does during shutdown, fails the request rather than leaving it unanswered.
     */
    @Test
    public void share_failsWhenAVisibilityRetryIsRejected() {
        // As the executor does: an AbstractRunnable is told of the rejection, any other task is dropped without a word
        doAnswer(inv -> {
            if (inv.getArgument(0) instanceof AbstractRunnable task) {
                task.onRejection(new OpenSearchRejectedExecutionException("shutting down", true));
            }
            return null;
        }).when(threadPool).schedule(any(Runnable.class), any(TimeValue.class), anyString());
        stubSharingAndResource(() -> recordJson(List.of()));
        stubRecordIndexSucceeds();
        stubUpdateBuilder();
        stubUpdateFails(ResourceSharingIndexHandlerTests::versionConflict);

        List<Exception> failures = new ArrayList<>();
        handler.share("res-1", RESOURCE_INDEX, shareWith("alice"), ActionListener.wrap(r -> {}, failures::add));

        assertEquals(1, failures.size());
    }

    /**
     * A caller whose success handler throws is not then told the request failed.
     */
    @Test
    public void share_completesTheCallerOnce() {
        stubSharingAndResource(() -> recordJson(List.of()));
        stubRecordIndexSucceeds();
        UpdateRequestBuilder builder = stubUpdateBuilder();
        stubUpdates(builder, value -> {});

        AtomicInteger responses = new AtomicInteger();
        AtomicInteger failures = new AtomicInteger();
        handler.share("res-1", RESOURCE_INDEX, shareWith("alice"), new ActionListener<>() {
            @Override
            public void onResponse(ResourceSharing r) {
                responses.incrementAndGet();
                throw new IllegalStateException("caller failed after success");
            }

            @Override
            public void onFailure(Exception e) {
                failures.incrementAndGet();
            }
        });

        assertEquals(1, responses.get());
        assertEquals(0, failures.get());
    }

    /**
     * A create that finds the record already there rewrites the field from that record, so a repeated migrate repairs it.
     */
    @Test
    public void create_onAnExistingRecordRewritesVisibilityFromIt() throws Exception {
        String existing = recordJson(List.of("alice", "bob"));
        stubSharingAndResource(() -> existing);
        stubRecordIndexConflicts();
        UpdateRequestBuilder builder = stubUpdateBuilder();
        List<List<String>> landed = new ArrayList<>();
        stubUpdates(builder, landed::add);

        ResourceSharing created = newRecord();
        List<Object> responses = new ArrayList<>();
        handler.indexResourceSharing(RESOURCE_INDEX, created, ActionListener.wrap(responses::add, e -> fail(e.toString())));

        assertEquals("an existing record is still reported as not created", 1, responses.size());
        assertNull(responses.get(0));
        assertEquals(1, landed.size());
        assertEquals(Set.copyOf(principalsOf(existing)), Set.copyOf(landed.get(0)));
    }

    @Test
    public void create_onAnExistingRecordReportsAFailureToWriteVisibility() throws Exception {
        stubSharingAndResource(() -> recordJson(List.of("alice")));
        stubRecordIndexConflicts();
        stubUpdateBuilder();
        stubUpdateFails(() -> new OpenSearchStatusException("mapping rejected the field", RestStatus.BAD_REQUEST));

        ResourceSharing created = newRecord();
        List<Exception> failures = new ArrayList<>();
        handler.indexResourceSharing(RESOURCE_INDEX, created, ActionListener.wrap(r -> fail("must not succeed"), failures::add));

        assertEquals(1, failures.size());
        assertTrue(failures.get(0).getMessage().contains("its sharing record was unchanged"));
        assertEquals("mapping rejected the field", failures.get(0).getCause().getMessage());
    }

    /**
     * The restore that follows a resource write starts from that write's version, so it needs no version read.
     */
    @Test
    public void restore_fromAKnownVersionSkipsTheVersionRead() {
        AtomicInteger resourceReads = new AtomicInteger();
        stubGets(() -> {
            resourceReads.incrementAndGet();
            return resourceDoc();
        }, () -> getResult(recordJson(List.of("alice")), 1L));
        UpdateRequestBuilder builder = stubUpdateBuilder();
        List<List<String>> landed = new ArrayList<>();
        stubUpdates(builder, landed::add);

        List<Object> done = new ArrayList<>();
        handler.fetchAndUpdateResourceVisibility("res-1", RESOURCE_INDEX, RESOURCE_DOC_SEQ_NO, 1L, ActionListener.wrap(done::add, e -> {
            fail(e.toString());
        }));

        assertEquals(1, done.size());
        assertEquals(0, resourceReads.get());
        assertEquals(1, landed.size());
        verify(builder).setIfSeqNo(RESOURCE_DOC_SEQ_NO);
    }

    /**
     * When the document has moved on since the write that started the restore, the restore reads the version again and
     * writes from the record as it then stands.
     */
    @Test
    public void restore_fromAStaleVersionRereadsTheVersion() throws Exception {
        runScheduledTasksInline();
        String current = recordJson(List.of("alice", "carol"));
        AtomicInteger resourceReads = new AtomicInteger();
        AtomicInteger recordReads = new AtomicInteger();
        stubGets(() -> {
            resourceReads.incrementAndGet();
            return resourceDoc();
        }, () -> getResult(recordReads.getAndIncrement() == 0 ? recordJson(List.of("alice")) : current, 1L));
        UpdateRequestBuilder builder = stubUpdateBuilder();
        List<List<String>> landed = new ArrayList<>();
        stubUpdates(builder, landed::add);

        List<Object> done = new ArrayList<>();
        handler.fetchAndUpdateResourceVisibility(
            "res-1",
            RESOURCE_INDEX,
            RESOURCE_DOC_SEQ_NO - 1,
            1L,
            ActionListener.wrap(done::add, e -> fail(e.toString()))
        );

        assertEquals(1, done.size());
        assertEquals(1, resourceReads.get());
        assertEquals("the retry reads the record again", 2, recordReads.get());
        assertEquals(1, landed.size());
        assertEquals(Set.copyOf(principalsOf(current)), Set.copyOf(landed.get(0)));
    }

    @Test
    public void create_onAnExistingRecordPassesThroughAMissingResourceDocument() throws Exception {
        stubGets(ResourceSharingIndexHandlerTests::missingResult, () -> getResult(recordJson(List.of("alice")), 1L));
        stubRecordIndexConflicts();
        stubUpdateBuilder();

        ResourceSharing created = newRecord();
        List<Exception> failures = new ArrayList<>();
        handler.indexResourceSharing(RESOURCE_INDEX, created, ActionListener.wrap(r -> fail("must not succeed"), failures::add));

        assertEquals(1, failures.size());
        assertTrue(failures.get(0) instanceof ResourceNotFoundException);
        verify(client, never()).update(any(UpdateRequest.class), any());
    }

    /**
     * The migrate API counts down a latch per completion, so the existing-record path must answer its caller once.
     */
    @Test
    public void create_onAnExistingRecordCompletesTheCallerOnce() throws Exception {
        stubSharingAndResource(() -> recordJson(List.of("alice")));
        stubRecordIndexConflicts();
        UpdateRequestBuilder builder = stubUpdateBuilder();
        stubUpdates(builder, value -> {});

        AtomicInteger responses = new AtomicInteger();
        AtomicInteger failures = new AtomicInteger();
        ResourceSharing created = newRecord();
        handler.indexResourceSharing(RESOURCE_INDEX, created, new ActionListener<>() {
            @Override
            public void onResponse(ResourceSharing r) {
                responses.incrementAndGet();
                throw new IllegalStateException("caller failed after success");
            }

            @Override
            public void onFailure(Exception e) {
                failures.incrementAndGet();
            }
        });

        assertEquals(1, responses.get());
        assertEquals(0, failures.get());
    }

    /**
     * A resource deleted after the write that started the restore is reported as missing, not as a failed field write.
     */
    @Test
    public void restore_fromAKnownVersionReportsADeletedResourceAsMissing() {
        stubSharingAndResource(() -> recordJson(List.of("alice")));
        stubUpdateBuilder();
        stubUpdateFails(() -> new DocumentMissingException(new ShardId(RESOURCE_INDEX, "_na_", 0), "res-1"));

        List<Exception> failures = new ArrayList<>();
        handler.fetchAndUpdateResourceVisibility("res-1", RESOURCE_INDEX, RESOURCE_DOC_SEQ_NO, 1L, ActionListener.wrap(r -> {
            fail("must not succeed");
        }, failures::add));

        assertEquals(1, failures.size());
        assertTrue(failures.get(0) instanceof ResourceNotFoundException);
    }

    // ---------- helpers for the visibility tests ------------------------------------------------------

    /**
     * Retries are scheduled on the generic pool. Running them inline lets a test drive the retry instead of waiting on it;
     * left unstubbed, the mock swallows the schedule and the retry never fires.
     */
    private void runScheduledTasksInline() {
        doAnswer(inv -> {
            ((Runnable) inv.getArgument(0)).run();
            return null;
        }).when(threadPool).schedule(any(Runnable.class), any(TimeValue.class), anyString());
    }

    private void stubRecordIndexSucceeds() {
        stubRecordIndexSucceeds(() -> {});
    }

    private void stubRecordIndexSucceeds(Runnable onIndexed) {
        stubRecordIndex(l -> {
            onIndexed.run();
            l.onResponse(mock(IndexResponse.class));
        });
    }

    private void stubRecordIndexConflicts() {
        stubRecordIndex(l -> l.onFailure(versionConflict()));
    }

    private void stubRecordIndex(Consumer<ActionListener<IndexResponse>> outcome) {
        IndexRequestBuilder indexBuilder = mock(IndexRequestBuilder.class, org.mockito.Answers.RETURNS_SELF);
        when(indexBuilder.request()).thenReturn(mock(IndexRequest.class));
        when(client.prepareIndex(anyString())).thenReturn(indexBuilder);
        doAnswer(inv -> {
            outcome.accept(inv.getArgument(1));
            return null;
        }).when(client).index(any(IndexRequest.class), any());
    }

    private void stubUpdateFails(Supplier<Exception> failure) {
        doAnswer(inv -> {
            ActionListener<UpdateResponse> l = inv.getArgument(1);
            l.onFailure(failure.get());
            return null;
        }).when(client).update(any(UpdateRequest.class), any());
    }

    private static VersionConflictEngineException versionConflict() {
        return new VersionConflictEngineException(new ShardId(RESOURCE_INDEX, "_na_", 0), "res-1", "moved on");
    }

    private static GetResult missingResult() {
        GetResult missing = mock(GetResult.class);
        when(missing.isExists()).thenReturn(false);
        return missing;
    }

    private UpdateRequestBuilder stubUpdateBuilder() {
        UpdateRequestBuilder builder = mock(UpdateRequestBuilder.class, org.mockito.Answers.RETURNS_SELF);
        when(builder.request()).thenReturn(mock(UpdateRequest.class));
        when(client.prepareUpdate(anyString(), anyString())).thenReturn(builder);
        return builder;
    }

    /** Answers resource-index GETs with the document at {@link #resourceSeqNo} and sharing-index GETs with the supplied record. */
    private void stubSharingAndResource(Supplier<String> recordSupplier) {
        stubGets(this::resourceDoc, () -> getResult(recordSupplier.get(), 1L));
    }

    private void stubGets(Supplier<GetResult> resource, Supplier<GetResult> record) {
        doAnswer(inv -> {
            GetRequest request = inv.getArgument(0);
            ActionListener<GetResponse> l = inv.getArgument(1);
            l.onResponse(new GetResponse(request.index().equals(RESOURCE_INDEX) ? resource.get() : record.get()));
            return null;
        }).when(client).get(any(GetRequest.class), any());
    }

    private GetResult resourceDoc() {
        return getResult("{\"name\":\"res\"}", resourceSeqNo.get());
    }

    /**
     * Applies an update the way the engine does: it lands only if its {@code ifSeqNo} matches the resource document's
     * current version, which it then advances, and is otherwise rejected with a version conflict.
     */
    @SuppressWarnings("unchecked")
    private void stubUpdates(UpdateRequestBuilder builder, Consumer<List<String>> onLanded) {
        AtomicLong ifSeqNo = new AtomicLong();
        AtomicReference<List<String>> principals = new AtomicReference<>();
        when(builder.setIfSeqNo(anyLong())).thenAnswer(inv -> {
            ifSeqNo.set(inv.getArgument(0));
            return builder;
        });
        when(builder.setDoc(any(Map.class))).thenAnswer(inv -> {
            principals.set(List.copyOf((List<String>) ((Map<String, Object>) inv.getArgument(0)).get("all_shared_principals")));
            return builder;
        });
        doAnswer(inv -> {
            ActionListener<UpdateResponse> l = inv.getArgument(1);
            if (ifSeqNo.get() != resourceSeqNo.get()) {
                l.onFailure(versionConflict());
                return null;
            }
            resourceSeqNo.incrementAndGet();
            onLanded.accept(principals.get());
            l.onResponse(mock(UpdateResponse.class));
            return null;
        }).when(client).update(any(UpdateRequest.class), any());
    }

    private static ResourceSharing newRecord() {
        return ResourceSharing.builder().resourceId("res-1").createdBy(new CreatedBy("creator")).build();
    }

    private ShareWith shareWith(String username) {
        return new ShareWith(Map.of("read_only", new Recipients(Map.of(Recipient.USERS, Set.of(username)))));
    }

    private String recordJson(List<String> sharedUsers) {
        String users = sharedUsers.stream().map(u -> "\"" + u + "\"").collect(Collectors.joining(","));
        String shareWith = sharedUsers.isEmpty() ? "{}" : "{\"read_only\":{\"users\":[" + users + "]}}";
        return "{\"created_by\":{\"user\":\"creator\"},\"resource_id\":\"res-1\",\"share_with\":" + shareWith + "}";
    }

    private List<String> principalsOf(String recordJson) throws Exception {
        try (
            XContentParser parser = XContentType.JSON.xContent()
                .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, recordJson)
        ) {
            parser.nextToken();
            return ResourceSharing.fromXContent(parser).getAllPrincipals();
        }
    }

    private GetResult getResult(String json, long seqNo) {
        GetResult getResult = mock(GetResult.class);
        when(getResult.getId()).thenReturn("res-1");
        when(getResult.isExists()).thenReturn(true);
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        BytesArray source = new BytesArray(bytes, 0, bytes.length);
        when(getResult.sourceRef()).thenReturn(source);
        when(getResult.sourceAsString()).thenReturn(json);
        when(getResult.sourceAsMap()).thenReturn(XContentHelper.convertToMap(source, false, XContentType.JSON).v2());
        when(getResult.getSeqNo()).thenReturn(seqNo);
        when(getResult.getPrimaryTerm()).thenReturn(1L);
        return getResult;
    }
}
