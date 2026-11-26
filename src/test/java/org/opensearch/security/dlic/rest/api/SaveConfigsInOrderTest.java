/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.dlic.rest.api;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.ClusterName;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.transport.client.Client;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;

/** Covers {@link AbstractApiAction#saveConfigsInOrderAsync}: write order, reverse-order undo, and partial failures. */
@RunWith(MockitoJUnitRunner.class)
public class SaveConfigsInOrderTest {

    private static final ShardId SECURITY_SHARD = new ShardId(".opendistro_security", "_na_", 0);

    @Mock
    Client client;

    private final SecurityApiDependencies dependencies = new SecurityApiDependencies(null, null, null, null, null, Settings.EMPTY);

    /** "id:ifSeqNo" of every index request, in order. Undo writes are the ones guarded by a 100+ _seq_no. */
    private final List<String> writes = new ArrayList<>();

    private final List<List<String>> reloads = new ArrayList<>();

    private final AtomicReference<IndexResponse> success = new AtomicReference<>();

    private final AtomicReference<Exception> failure = new AtomicReference<>();

    @Test
    public void writesInOrderAndLeavesReloadToCaller() throws Exception {
        writeOutcomes(null, null, null);

        AbstractApiAction.saveConfigsInOrderAsync(dependencies, client, threeWrites(), listener());

        assertThat(writes, contains("internalusers:1", "rolesmapping:2", "roles:3"));
        assertThat(success.get().getId(), is("roles"));
        assertThat(reloads.isEmpty(), is(true));
    }

    @Test
    public void failedWriteUndoesCompletedWritesInReverseOrder() throws Exception {
        writeOutcomes(null, null, conflict(), null, null);
        reloadsSucceed();

        AbstractApiAction.saveConfigsInOrderAsync(dependencies, client, threeWrites(), listener());

        // Undo writes are guarded by the _seq_no our own writes produced (100, 101), newest first.
        assertThat(writes, contains("internalusers:1", "rolesmapping:2", "roles:3", "rolesmapping:101", "internalusers:100"));
        assertThat(reloads, contains(List.of("internalusers", "rolesmapping")));
        assertThat(success.get(), is(nullValue()));
        assertThat(failure.get(), instanceOf(VersionConflictEngineException.class));
    }

    @Test
    public void failedUndoReportsPartiallyAppliedAndStops() throws Exception {
        writeOutcomes(null, null, conflict(), conflict());

        AbstractApiAction.saveConfigsInOrderAsync(dependencies, client, threeWrites(), listener());

        // The rolesmapping undo fails, so internalusers is not touched again and nothing is reloaded.
        assertThat(writes, contains("internalusers:1", "rolesmapping:2", "roles:3", "rolesmapping:101"));
        assertThat(reloads.isEmpty(), is(true));
        assertThat(failure.get(), instanceOf(AbstractApiAction.PartiallyAppliedConfigWriteException.class));
        assertThat(failure.get().getMessage().contains("[internalusers, rolesmapping]"), is(true));
        assertThat(
            ((AbstractApiAction.PartiallyAppliedConfigWriteException) failure.get()).notRestored(),
            contains("internalusers", "rolesmapping")
        );
    }

    @Test
    public void failedFirstWriteReportsFailureWithoutUndo() throws Exception {
        writeOutcomes(conflict());

        AbstractApiAction.saveConfigsInOrderAsync(dependencies, client, threeWrites(), listener());

        assertThat(writes, contains("internalusers:1"));
        assertThat(reloads.isEmpty(), is(true));
        assertThat(failure.get(), instanceOf(VersionConflictEngineException.class));
    }

    private List<AbstractApiAction.ConfigWrite> threeWrites() throws Exception {
        return List.of(write(CType.INTERNALUSERS, 1), write(CType.ROLESMAPPING, 2), write(CType.ROLES, 3));
    }

    /** A write whose original and updated documents are both empty configs read at {@code seqNo}. */
    private static AbstractApiAction.ConfigWrite write(final CType<?> cType, final long seqNo) throws Exception {
        final String json = "{\"_meta\":{\"type\":\"" + cType.toLCString() + "\",\"config_version\":2}}";
        return new AbstractApiAction.ConfigWrite(
            cType,
            SecurityDynamicConfiguration.fromJson(json, cType, 2, seqNo, 1),
            SecurityDynamicConfiguration.fromJson(json, cType, 2, seqNo, 1)
        );
    }

    private ActionListener<IndexResponse> listener() {
        return ActionListener.wrap(success::set, failure::set);
    }

    /** One outcome per index call, in order: null means success (with _seq_no 100 + call number), otherwise the failure. */
    private void writeOutcomes(final Exception... outcomes) {
        doAnswer(invocation -> {
            final IndexRequest request = invocation.getArgument(0);
            final ActionListener<IndexResponse> indexListener = invocation.getArgument(1);
            writes.add(request.id() + ":" + request.ifSeqNo());
            final var outcome = outcomes[writes.size() - 1];
            if (outcome == null) {
                indexListener.onResponse(new IndexResponse(SECURITY_SHARD, request.id(), 100 + writes.size() - 1, 1, 1, false));
            } else {
                indexListener.onFailure(outcome);
            }
            return null;
        }).when(client).index(any(IndexRequest.class), any());
    }

    private void reloadsSucceed() {
        doAnswer(invocation -> {
            final ConfigUpdateRequest request = invocation.getArgument(1);
            final ActionListener<ConfigUpdateResponse> reloadListener = invocation.getArgument(2);
            reloads.add(Arrays.asList(request.getConfigTypes()));
            reloadListener.onResponse(new ConfigUpdateResponse(ClusterName.DEFAULT, List.of(), List.of()));
            return null;
        }).when(client).execute(eq(ConfigUpdateAction.INSTANCE), any(ConfigUpdateRequest.class), any());
    }

    private void reloadsFail() {
        doAnswer(invocation -> {
            final ConfigUpdateRequest request = invocation.getArgument(1);
            final ActionListener<ConfigUpdateResponse> reloadListener = invocation.getArgument(2);
            reloads.add(Arrays.asList(request.getConfigTypes()));
            reloadListener.onFailure(new IllegalStateException("reload failed"));
            return null;
        }).when(client).execute(eq(ConfigUpdateAction.INSTANCE), any(ConfigUpdateRequest.class), any());
    }

    @Test
    public void failedRestoreReloadReportsPartiallyApplied() throws Exception {
        // Writes succeed up to a failure, the restores succeed, but the reload of the restored types fails —
        // nodes may keep the stale in-memory state, so the caller must learn about it.
        writeOutcomes(null, null, conflict(), null, null);
        reloadsFail();

        AbstractApiAction.saveConfigsInOrderAsync(dependencies, client, threeWrites(), listener());

        assertThat(writes, contains("internalusers:1", "rolesmapping:2", "roles:3", "rolesmapping:101", "internalusers:100"));
        assertThat(reloads, contains(List.of("internalusers", "rolesmapping")));
        assertThat(success.get(), is(nullValue()));
        assertThat(failure.get(), instanceOf(AbstractApiAction.PartiallyAppliedConfigWriteException.class));
        // Every write was restored, so no config type is left holding the batch's update.
        assertThat(((AbstractApiAction.PartiallyAppliedConfigWriteException) failure.get()).notRestored(), is(empty()));
    }

    private static Exception conflict() {
        return new VersionConflictEngineException(SECURITY_SHARD, "doc", "version conflict");
    }
}
