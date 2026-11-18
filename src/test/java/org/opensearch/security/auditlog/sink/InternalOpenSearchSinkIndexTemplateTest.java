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

import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for how {@link InternalOpenSearchSink} uses its {@link AuditLogIndexTemplate}.
 *
 * @see AuditLogIndexTemplateTest for the index template itself
 */
public class InternalOpenSearchSinkIndexTemplateTest {

    private static final String PREFIX = "plugins.security.audit.config";
    private static final String TODAY_INDEX = "security-auditlog-2026.11.05";

    @Mock
    private ClusterService clusterService;
    @Mock
    private ClusterState clusterState;
    @Mock
    private Metadata metadata;
    @Mock
    private Client client;
    @Mock
    private AdminClient adminClient;
    @Mock
    private IndicesAdminClient indicesAdminClient;
    @Mock
    private ThreadPool threadPool;
    @Mock
    private ActionFuture<AcknowledgedResponse> putTemplateFuture;
    @Mock
    private ActionFuture<CreateIndexResponse> createIndexFuture;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        when(clusterService.state()).thenReturn(clusterState);
        when(clusterState.metadata()).thenReturn(metadata);
        when(metadata.templatesV2()).thenReturn(Map.of());
        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        doReturn(new AcknowledgedResponse(true)).when(putTemplateFuture).actionGet();
        doReturn(putTemplateFuture).when(client).execute(eq(PutComposableIndexTemplateAction.INSTANCE), any());
        doReturn(new CreateIndexResponse(true, true, TODAY_INDEX)).when(createIndexFuture).actionGet();
        when(indicesAdminClient.create(any(CreateIndexRequest.class))).thenReturn(createIndexFuture);
    }

    private InternalOpenSearchSink sink(String name, Settings sinkSettings) {
        Settings settings = Settings.builder().put(sinkSettings, false).normalizePrefix(PREFIX + ".").build();
        return new InternalOpenSearchSink(name, settings, PREFIX, null, client, threadPool, null, clusterService);
    }

    private static Settings enabled() {
        return Settings.builder().put("index_template.enabled", true).build();
    }

    @Test
    public void templateIsDisabledByDefault() {
        InternalOpenSearchSink sink = sink("default", Settings.EMPTY);

        assertThat(sink.indexTemplate, is(nullValue()));
        assertThat(sink.createIndexIfAbsent(TODAY_INDEX), is(true));
        verify(client, never()).execute(eq(PutComposableIndexTemplateAction.INSTANCE), any());
    }

    @Test
    public void templateUsesSinkNameAndDefaultIndexPattern() {
        InternalOpenSearchSink sink = sink("Archive", enabled());

        assertThat(sink.indexTemplate.name(), is("security-auditlog-archive"));
        assertThat(sink.indexTemplate.indexPatterns(), contains("security-auditlog-*"));
    }

    @Test
    public void noTemplateWhenPatternCannotBeDerived() {
        InternalOpenSearchSink sink = sink(
            "default",
            Settings.builder().put("index_template.enabled", true).put("index", "YYYY.MM.dd'-audit'").build()
        );

        assertThat(sink.indexTemplate, is(nullValue()));
    }

    @Test
    public void createsTemplateBeforeCreatingIndex() {
        assertThat(sink("default", enabled()).createIndexIfAbsent(TODAY_INDEX), is(true));

        InOrder order = inOrder(client, indicesAdminClient);
        order.verify(client).execute(eq(PutComposableIndexTemplateAction.INSTANCE), any());
        order.verify(indicesAdminClient).create(any(CreateIndexRequest.class));
    }

    @Test
    public void createsTemplateWhenTodaysIndexAlreadyExists() {
        when(metadata.hasIndex(TODAY_INDEX)).thenReturn(true);

        assertThat(sink("default", enabled()).createIndexIfAbsent(TODAY_INDEX), is(true));

        verify(client).execute(eq(PutComposableIndexTemplateAction.INSTANCE), any());
        verify(indicesAdminClient, never()).create(any(CreateIndexRequest.class));
    }

    @Test
    public void failsWhenTemplateCannotBeCreated() {
        when(putTemplateFuture.actionGet()).thenThrow(new IllegalArgumentException("overlapping template with the same priority"));

        assertThat(sink("default", enabled()).createIndexIfAbsent(TODAY_INDEX), is(false));

        verify(indicesAdminClient, never()).create(any(CreateIndexRequest.class));
    }

    @Test
    public void failsWhenTemplateCannotBeCreatedAndIndexAlreadyExists() {
        when(metadata.hasIndex(TODAY_INDEX)).thenReturn(true);
        when(putTemplateFuture.actionGet()).thenThrow(new IllegalArgumentException("overlapping template with the same priority"));

        assertThat(sink("default", enabled()).createIndexIfAbsent(TODAY_INDEX), is(false));
    }

    @Test
    public void doesNotCreateTemplateForAliasTarget() {
        InternalOpenSearchSink sink = sink(
            "default",
            Settings.builder().put("index_template.enabled", true).put("index", "security-audit-write-alias").build()
        );
        when(metadata.hasAlias("security-audit-write-alias")).thenReturn(true);

        assertThat(sink.createIndexIfAbsent("security-audit-write-alias"), is(true));

        verify(client, never()).execute(eq(PutComposableIndexTemplateAction.INSTANCE), any());
    }
}
