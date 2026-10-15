/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.util.List;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StringField;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexRequestBuilder;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.mapper.ParseContext;
import org.opensearch.index.mapper.ParsedDocument;
import org.opensearch.security.resources.settings.ResourceSharingFeatureFlagSetting;
import org.opensearch.security.resources.settings.ResourceSharingProtectedResourcesSetting;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import org.mockito.Answers;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests that {@link ResourceIndexListener} creates a sharing record only for a document of a registered, protected type.
 */
public class ResourceIndexListenerTests {

    private static final String INDEX = ".alerting-config";
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

        resourcePluginInfo = new ResourcePluginInfo();
        resourcePluginInfo.setProtectedTypesSetting(setting(List.of("monitor", "alerting-workflow")));
        resourcePluginInfo.setResourceSharingExtensions(Set.of(alertingExtension()));

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

    private void create(String id, StringField... fields) {
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
        Engine.IndexResult result = mock(Engine.IndexResult.class);
        when(result.isCreated()).thenReturn(true);

        listener.postIndex(new ShardId(INDEX, "uuid", 0), index, result);
    }

    /** alerting's two providers as alerting declares them. */
    private static ResourceSharingExtension alertingExtension() {
        return new ResourceSharingExtension() {
            @Override
            public Set<ResourceProvider> getResourceProviders() {
                return Set.of(provider("monitor", "monitor.type"), provider("alerting-workflow", "workflow.type", "workflow"));
            }

            @Override
            public void assignResourceSharingClient(ResourceSharingClient client) {}
        };
    }

    private static ResourceProvider provider(String type, String typeField) {
        return provider(type, typeField, type);
    }

    private static ResourceProvider provider(String type, String typeField, String typeFieldValue) {
        return new ResourceProvider() {
            @Override
            public String typeFieldValue() {
                return typeFieldValue;
            }

            @Override
            public String resourceType() {
                return type;
            }

            @Override
            public String resourceIndexName() {
                return INDEX;
            }

            @Override
            public String typeField() {
                return typeField;
            }
        };
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
