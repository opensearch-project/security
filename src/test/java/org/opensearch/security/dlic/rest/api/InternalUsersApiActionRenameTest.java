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
import java.util.Base64;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestResponse;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.hasher.PasswordHasherFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.user.UserService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import tools.jackson.databind.JsonNode;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Covers the write path of the internal-user rename: write ordering, the undo of the internalusers
 * write when the rolesmapping write fails, and reporting when the undo itself fails. These failures
 * can't be triggered on demand against a real cluster, so the client is faked.
 */
@RunWith(MockitoJUnitRunner.class)
public class InternalUsersApiActionRenameTest {

    private static final String HASH = "$2y$12$88IFVl6IfIwCFh5aQYfOmuXVL9j2hz/GusQb35o.4sdTDAEMTOD.K";

    private static final ShardId SECURITY_SHARD = new ShardId(".opendistro_security", "_na_", 0);

    @Mock
    ClusterService clusterService;

    @Mock
    ThreadPool threadPool;

    @Mock
    ConfigurationRepository configurationRepository;

    @Mock
    RestApiAuthorizationEvaluator restApiAuthorizationEvaluator;

    @Mock
    AuditLog auditLog;

    @Mock
    UserService userService;

    @Mock
    Client client;

    @Mock
    RestChannel channel;

    private InternalUsersApiAction action;

    /** Every index request the code under test sent, in order. */
    private final List<IndexRequest> writes = new ArrayList<>();

    /** Config types named by every reload request, in order. */
    private final List<List<String>> reloads = new ArrayList<>();

    @Before
    public void setup() {
        final var dependencies = new SecurityApiDependencies(
            null,
            configurationRepository,
            null,
            restApiAuthorizationEvaluator,
            auditLog,
            Settings.EMPTY
        );
        action = new InternalUsersApiAction(
            clusterService,
            threadPool,
            userService,
            dependencies,
            PasswordHasherFactory.createPasswordHasher(
                Settings.builder().put(PasswordHasherFactory.ALGORITHM.getKey(), PasswordHasherFactory.BCRYPT).build()
            )
        );
    }

    @Test
    public void successfulRenameWritesUsersThenMappingsThenReloadsBoth() throws Exception {
        writeOutcomes(null, null);
        reloadsSucceed();

        action.executeRename(channel, client, plan(), "admin");

        assertThat(writtenDocIds(), contains("internalusers", "rolesmapping"));
        // Both writes carry the _seq_no guard from when the documents were read.
        assertThat(writes.get(0).ifSeqNo(), is(10L));
        assertThat(writes.get(1).ifSeqNo(), is(20L));
        assertThat(usernames(writes.get(0)), containsInAnyOrder("alice2", "bob"));
        assertThat(reloads, contains(List.of("internalusers", "rolesmapping")));
        assertThat(sentResponse().status(), is(RestStatus.OK));
        verify(auditLog).logInternalUserRenamed("alice", "alice2", List.of("readall"), true, "admin");
    }

    @Test
    public void failedRoleMappingWriteRestoresOriginalUsers() throws Exception {
        // Write 1 (users) succeeds, write 2 (mappings) loses a race with another admin, write 3 (undo) succeeds.
        writeOutcomes(null, conflict(), null);
        reloadsSucceed();

        action.executeRename(channel, client, plan(), "admin");

        assertThat(writtenDocIds(), contains("internalusers", "rolesmapping", "internalusers"));
        final var undo = writes.get(2);
        // The undo is guarded by the _seq_no of our own write #1 (fake responses use 100 + call number),
        // so it can't overwrite a change someone else made after it.
        assertThat(undo.ifSeqNo(), is(100L));
        assertThat(undo.ifPrimaryTerm(), is(1L));
        // ...and it puts back the original document: alice, not alice2.
        assertThat(usernames(undo), containsInAnyOrder("alice", "bob"));
        // Nodes reload internalusers so none keeps the intermediate state.
        assertThat(reloads, contains(List.of("internalusers")));
        final var response = sentResponse();
        assertThat(response.status(), is(RestStatus.CONFLICT));
        assertThat(response.content().utf8ToString(), containsString("version conflict"));
        // Net state is unchanged, so there's no rename to audit.
        verifyNoInteractions(auditLog);
    }

    @Test
    public void failedUndoReportsPartialRename() throws Exception {
        writeOutcomes(null, conflict(), conflict());

        action.executeRename(channel, client, plan(), "admin");

        assertThat(writtenDocIds(), contains("internalusers", "rolesmapping", "internalusers"));
        assertThat(reloads, is(empty()));
        final var response = sentResponse();
        assertThat(response.status(), is(RestStatus.INTERNAL_SERVER_ERROR));
        assertThat(response.content().utf8ToString(), containsString("partially applied"));
        assertThat(response.content().utf8ToString(), containsString("readall"));
        // The config really did change, so the partial state is audited: readall still lists alice.
        verify(auditLog).logInternalUserRenamed("alice", "alice2", List.of("readall"), false, "admin");
    }

    @Test
    public void failedReloadAfterRestoreReportsRollbackNotPartialRename() throws Exception {
        // The rolesmapping write fails and internalusers is restored, but reloading the restored config fails.
        // Nothing is renamed on disk, so the response must not tell the admin to edit role mappings by hand.
        writeOutcomes(null, conflict(), null);
        reloadsFail();

        action.executeRename(channel, client, plan(), "admin");

        assertThat(writtenDocIds(), contains("internalusers", "rolesmapping", "internalusers"));
        final var response = sentResponse();
        assertThat(response.status(), is(RestStatus.INTERNAL_SERVER_ERROR));
        assertThat(response.content().utf8ToString(), containsString("rolled back"));
        assertThat(response.content().utf8ToString().contains("Update them manually"), is(false));
        verifyNoInteractions(auditLog);
    }

    @Test
    public void failedUsersWriteStopsBeforeTouchingMappings() throws Exception {
        writeOutcomes(conflict());

        action.executeRename(channel, client, plan(), "admin");

        assertThat(writtenDocIds(), contains("internalusers"));
        assertThat(reloads, is(empty()));
        assertThat(sentResponse().status(), is(RestStatus.CONFLICT));
        verifyNoInteractions(auditLog);
    }

    // ---------------------------------------------------------------------------------------------

    /** alice -> alice2; the "readall" mapping lists alice and bob. Documents read at _seq_no 10 and 20. */
    private InternalUsersApiAction.RenamePlan plan() throws Exception {
        final var users = SecurityDynamicConfiguration.fromJson(
            "{\"_meta\":{\"type\":\"internalusers\",\"config_version\":2},"
                + "\"alice\":{\"hash\":\""
                + HASH
                + "\"},\"bob\":{\"hash\":\""
                + HASH
                + "\"}}",
            CType.INTERNALUSERS,
            2,
            10,
            1
        );
        final var mappings = SecurityDynamicConfiguration.fromJson(
            "{\"_meta\":{\"type\":\"rolesmapping\",\"config_version\":2},\"readall\":{\"users\":[\"alice\",\"bob\"]}}",
            CType.ROLESMAPPING,
            2,
            20,
            1
        );
        final var result = action.planRename("alice", "alice2", users, mappings);
        assertThat(result.isValid(), is(true));
        final List<InternalUsersApiAction.RenamePlan> plan = new ArrayList<>();
        result.valid(plan::add);
        return plan.get(0);
    }

    /** One outcome per index call, in order: null means success, otherwise the failure to report. */
    private void writeOutcomes(final Exception... outcomes) {
        doAnswer(invocation -> {
            final IndexRequest request = invocation.getArgument(0);
            final ActionListener<IndexResponse> listener = invocation.getArgument(1);
            writes.add(request);
            final var outcome = outcomes[writes.size() - 1];
            if (outcome == null) {
                listener.onResponse(new IndexResponse(SECURITY_SHARD, request.id(), 100 + writes.size() - 1, 1, 1, false));
            } else {
                listener.onFailure(outcome);
            }
            return null;
        }).when(client).index(any(IndexRequest.class), any());
    }

    private void reloadsSucceed() {
        doAnswer(invocation -> {
            final ConfigUpdateRequest request = invocation.getArgument(1);
            final ActionListener<ConfigUpdateResponse> listener = invocation.getArgument(2);
            reloads.add(Arrays.asList(request.getConfigTypes()));
            listener.onResponse(new ConfigUpdateResponse(ClusterName.DEFAULT, List.of(), List.of()));
            return null;
        }).when(client).execute(eq(ConfigUpdateAction.INSTANCE), any(ConfigUpdateRequest.class), any());
    }

    private void reloadsFail() {
        doAnswer(invocation -> {
            final ConfigUpdateRequest request = invocation.getArgument(1);
            final ActionListener<ConfigUpdateResponse> listener = invocation.getArgument(2);
            reloads.add(Arrays.asList(request.getConfigTypes()));
            listener.onFailure(new IllegalStateException("reload failed"));
            return null;
        }).when(client).execute(eq(ConfigUpdateAction.INSTANCE), any(ConfigUpdateRequest.class), any());
    }

    private static Exception conflict() {
        return new VersionConflictEngineException(SECURITY_SHARD, "doc", "version conflict");
    }

    private List<String> writtenDocIds() {
        return writes.stream().map(IndexRequest::id).toList();
    }

    /** Decodes the config document inside an index request and returns its user names. */
    private static List<String> usernames(final IndexRequest request) throws Exception {
        final JsonNode source = DefaultObjectMapper.readTree(request.source().utf8ToString());
        final JsonNode document = DefaultObjectMapper.readTree(
            new String(Base64.getDecoder().decode(source.get("internalusers").asText()))
        );
        final List<String> names = new ArrayList<>();
        document.propertyNames().forEach(name -> {
            if (!"_meta".equals(name)) {
                names.add(name);
            }
        });
        return names;
    }

    private RestResponse sentResponse() throws Exception {
        final ArgumentCaptor<RestResponse> captor = ArgumentCaptor.forClass(RestResponse.class);
        verify(channel).sendResponse(captor.capture());
        return captor.getValue();
    }

    @Before
    public void channelBuildsJson() throws Exception {
        when(channel.newBuilder()).thenAnswer(invocation -> XContentFactory.jsonBuilder());
    }
}
