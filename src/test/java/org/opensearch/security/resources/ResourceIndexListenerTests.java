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
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StringField;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexRequestBuilder;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateRequestBuilder;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.get.GetResult;
import org.opensearch.index.mapper.ParseContext;
import org.opensearch.index.mapper.ParsedDocument;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.security.resources.settings.ResourceSharingFeatureFlagSetting;
import org.opensearch.security.resources.settings.ResourceSharingProtectedResourcesSetting;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import org.mockito.Answers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests that {@link ResourceIndexListener} creates a sharing record only for a document of a registered, protected type,
 * and restores visibility after a write to an existing resource.
 */
public class ResourceIndexListenerTests {

    private static final String INDEX = ResourceProviderFixtures.ALERTING_INDEX;
    private static final String SHARING_INDEX = ResourceSharingIndexHandler.getSharingIndex(INDEX);

    private Client client;
    private IndexRequestBuilder records;
    private ResourcePluginInfo resourcePluginInfo;
    private ResourceIndexListener listener;

    @Before
    public void setUp() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER,
            new User("alice", ImmutableSet.of(), ImmutableSet.of(), null, ImmutableMap.of(), false)
        );
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(threadContext);

        // The handler builds its request through prepareIndex(...).set...().request(); setId shows which resource it was for
        client = mock(Client.class);
        records = mock(IndexRequestBuilder.class, Answers.RETURNS_SELF);
        when(records.request()).thenReturn(mock(IndexRequest.class));
        when(client.prepareIndex(any())).thenReturn(records);
        // The sharing index already exists, so the handler writes the record without creating it
        AdminClient adminClient = mock(AdminClient.class);
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        doAnswer(inv -> {
            ActionListener<IndicesExistsResponse> l = inv.getArgument(1);
            l.onResponse(new IndicesExistsResponse(true));
            return null;
        }).when(indicesAdminClient).exists(any(IndicesExistsRequest.class), any());

        resourcePluginInfo = new ResourcePluginInfo();
        resourcePluginInfo.setProtectedTypesSetting(setting(List.of("monitor", "alerting-workflow")));
        resourcePluginInfo.setResourceSharingExtensions(Set.of(ResourceProviderFixtures.alertingExtension()));

        listener = new ResourceIndexListener(threadPool, client, resourcePluginInfo, booleanSetting(true));
    }

    @Test
    public void createsARecordForAProtectedType() {
        create("workflow-1", new StringField("workflow.type", "workflow", Field.Store.NO));

        verify(client).prepareIndex(SHARING_INDEX);
        verify(records).setId("workflow-1");
    }

    @Test
    public void createsNoRecordForADocumentOfNoRegisteredType() {
        create("metadata-1", new StringField("metadata.monitor_id", "monitor-1", Field.Store.NO));

        verify(client, never()).prepareIndex(any());
    }

    /**
     * A write to an existing resource restores its visibility from the version that write produced, without reading it.
     */
    @Test
    public void anUpdateRestoresVisibilityFromTheVersionItWrote() {
        List<String> readIndices = stubRecordRead();
        UpdateRequestBuilder visibility = mock(UpdateRequestBuilder.class, Answers.RETURNS_SELF);
        when(visibility.request()).thenReturn(mock(UpdateRequest.class));
        when(client.prepareUpdate(any(), any())).thenReturn(visibility);

        update("workflow-1", Engine.Result.Type.SUCCESS, 9L, 2L);

        assertFalse("the resource document's version must not be read", readIndices.contains(INDEX));
        verify(visibility).setIfSeqNo(9L);
        verify(visibility).setIfPrimaryTerm(2L);
    }

    @Test
    public void aFailedWriteReadsTheVersion() {
        List<String> readIndices = stubRecordRead();

        update("workflow-1", Engine.Result.Type.FAILURE, 9L, 2L);

        assertEquals("the version is read before the record", INDEX, readIndices.get(0));
    }

    @Test
    public void aWriteWithoutAnAssignedSeqNoReadsTheVersion() {
        List<String> readIndices = stubRecordRead();

        update("workflow-1", Engine.Result.Type.SUCCESS, SequenceNumbers.UNASSIGNED_SEQ_NO, 0L);

        assertEquals("the version is read before the record", INDEX, readIndices.get(0));
    }

    /** Records the index of every GET and answers a sharing-index GET with a record. */
    private List<String> stubRecordRead() {
        List<String> readIndices = new ArrayList<>();
        doAnswer(inv -> {
            GetRequest request = inv.getArgument(0);
            readIndices.add(request.index());
            if (request.index().equals(SHARING_INDEX)) {
                String json = "{\"resource_id\":\"workflow-1\",\"created_by\":{\"user\":\"alice\"}}";
                GetResult record = mock(GetResult.class);
                when(record.isExists()).thenReturn(true);
                when(record.sourceAsString()).thenReturn(json);
                byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
                when(record.sourceRef()).thenReturn(new BytesArray(bytes, 0, bytes.length));
                ActionListener<GetResponse> l = inv.getArgument(1);
                l.onResponse(new GetResponse(record));
            }
            return null;
        }).when(client).get(any(GetRequest.class), any());
        return readIndices;
    }

    private void update(String id, Engine.Result.Type resultType, long seqNo, long primaryTerm) {
        Engine.IndexResult result = mock(Engine.IndexResult.class);
        when(result.isCreated()).thenReturn(false);
        when(result.getResultType()).thenReturn(resultType);
        when(result.getSeqNo()).thenReturn(seqNo);
        when(result.getTerm()).thenReturn(primaryTerm);

        listener.postIndex(
            new ShardId(INDEX, "uuid", 0),
            indexOp(id, new StringField("workflow.type", "workflow", Field.Store.NO)),
            result
        );
    }

    private void create(String id, StringField... fields) {
        Engine.IndexResult result = mock(Engine.IndexResult.class);
        when(result.isCreated()).thenReturn(true);

        listener.postIndex(new ShardId(INDEX, "uuid", 0), indexOp(id, fields), result);
    }

    private static Engine.Index indexOp(String id, StringField... fields) {
        ParseContext.Document rootDoc = new ParseContext.Document();
        for (StringField field : fields) {
            rootDoc.add(field);
        }
        ParsedDocument parsedDoc = mock(ParsedDocument.class);
        when(parsedDoc.rootDoc()).thenReturn(rootDoc);
        Engine.Index index = mock(Engine.Index.class);
        when(index.id()).thenReturn(id);
        when(index.parsedDoc()).thenReturn(parsedDoc);
        when(index.origin()).thenReturn(Engine.Operation.Origin.PRIMARY);
        return index;
    }

    private static OpensearchDynamicSetting<List<String>> setting(List<String> protectedTypes) {
        return new OpensearchDynamicSetting<>(ResourceSharingProtectedResourcesSetting.PROTECTED_TYPES, protectedTypes) {
        };
    }

    private static OpensearchDynamicSetting<Boolean> booleanSetting(boolean value) {
        return new OpensearchDynamicSetting<>(ResourceSharingFeatureFlagSetting.RESOURCE_SHARING_ENABLED, value) {
        };
    }
}
