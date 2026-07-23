/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.apache.lucene.document.Field;
import org.apache.lucene.document.StringField;
import org.apache.lucene.index.IndexableField;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.index.engine.Engine;
import org.opensearch.index.mapper.ParsedDocument;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ResourcePluginInfo#getResourceTypeForIndexOp}.
 */
public class ResourcePluginInfoTests {

    private ResourcePluginInfo resourcePluginInfo;

    @Before
    public void setUp() {
        resourcePluginInfo = new ResourcePluginInfo();
    }

    @Test
    public void testSingleProviderNoTypeField() {
        registerProviders(List.of("monitor"), ".alerting-config", null);
        resourcePluginInfo.updateProtectedTypes(List.of("monitor"));

        Engine.Index indexOp = mockIndexOp();
        String result = resourcePluginInfo.getResourceTypeForIndexOp(".alerting-config", indexOp);
        assertEquals("monitor", result);
    }

    @Test
    public void testSingleProviderWithTypeField() {
        registerProviders(List.of("monitor"), ".alerting-config", "monitor.type");
        resourcePluginInfo.updateProtectedTypes(List.of("monitor"));

        Engine.Index indexOp = mockMonitorDoc();
        String result = resourcePluginInfo.getResourceTypeForIndexOp(".alerting-config", indexOp);
        assertEquals("monitor", result);
    }

    @Test
    public void testMultipleProvidersFirstProviderResolves() {
        registerProviders("monitor", "monitor.type", "workflow", "workflow.type", ".alerting-config");
        resourcePluginInfo.updateProtectedTypes(Arrays.asList("monitor", "workflow"));

        Engine.Index indexOp = mockMonitorDoc();
        String result = resourcePluginInfo.getResourceTypeForIndexOp(".alerting-config", indexOp);
        assertEquals("monitor", result);
    }

    @Test
    public void testMultipleProvidersSecondProviderResolves() {
        registerProviders("monitor", "monitor.type", "workflow", "workflow.type", ".alerting-config");
        resourcePluginInfo.updateProtectedTypes(Arrays.asList("monitor", "workflow"));

        Engine.Index indexOp = mockWorkflowDoc();
        String result = resourcePluginInfo.getResourceTypeForIndexOp(".alerting-config", indexOp);
        assertEquals("workflow", result);
    }

    @Test
    public void testMultipleProvidersNeitherResolves() {
        registerProviders("monitor", "monitor.type", "workflow", "workflow.type", ".alerting-config");
        resourcePluginInfo.updateProtectedTypes(Arrays.asList("monitor", "workflow"));

        // A metadata doc — no monitor.* or workflow.* fields, just top-level metadata.*
        Engine.Index indexOp = mockIndexOp(new StringField("metadata.monitor_id", "abc123", Field.Store.NO));
        String result = resourcePluginInfo.getResourceTypeForIndexOp(".alerting-config", indexOp);
        assertNull(result);
    }

    @Test
    public void testUnknownIndexReturnsNull() {
        registerProviders(List.of("monitor"), ".alerting-config", "monitor.type");
        resourcePluginInfo.updateProtectedTypes(List.of("monitor"));

        Engine.Index indexOp = mockMonitorDoc();
        String result = resourcePluginInfo.getResourceTypeForIndexOp(".some-other-index", indexOp);
        assertNull(result);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────────

    private void registerProviders(List<String> types, String indexName, String sharedTypeField) {
        ResourceSharingExtension extension = new ResourceSharingExtension() {
            @Override
            public Set<ResourceProvider> getResourceProviders() {
                var providers = new java.util.LinkedHashSet<ResourceProvider>();
                for (String type : types) {
                    providers.add(new ResourceProvider() {
                        @Override
                        public String resourceType() {
                            return type;
                        }

                        @Override
                        public String resourceIndexName() {
                            return indexName;
                        }

                        @Override
                        public String typeField() {
                            return sharedTypeField;
                        }
                    });
                }
                return providers;
            }

            @Override
            public void assignResourceSharingClient(ResourceSharingClient client) {}
        };
        resourcePluginInfo.setResourceSharingExtensions(Set.of(extension));
    }

    private void registerProviders(String type1, String tf1, String type2, String tf2, String indexName) {
        ResourceSharingExtension extension = new ResourceSharingExtension() {
            @Override
            public Set<ResourceProvider> getResourceProviders() {
                var providers = new java.util.LinkedHashSet<ResourceProvider>();
                providers.add(makeProvider(type1, indexName, tf1));
                providers.add(makeProvider(type2, indexName, tf2));
                return providers;
            }

            @Override
            public void assignResourceSharingClient(ResourceSharingClient client) {}
        };
        resourcePluginInfo.setResourceSharingExtensions(Set.of(extension));
    }

    private ResourceProvider makeProvider(String type, String index, String typeField) {
        return new ResourceProvider() {
            @Override
            public String resourceType() {
                return type;
            }

            @Override
            public String resourceIndexName() {
                return index;
            }

            @Override
            public String typeField() {
                return typeField;
            }
        };
    }

    /**
     * Builds an {@link Engine.Index} mock whose {@code parsedDoc().rootDoc()} contains the flat
     * set of Lucene fields that the alerting plugin's mapper would produce for a real monitor
     * document. The source JSON stored in {@code .opendistro-alerting-config} for a monitor looks
     * like:
     *
     * <pre>{@code
     * {
     *   "monitor": {
     *     "type": "monitor",
     *     "schema_version": 8,
     *     "name": "my-monitor",
     *     "monitor_type": "query_level_monitor",
     *     "user": { "name": "alice", "backend_roles": ["engineering"] },
     *     "enabled": true,
     *     "schedule": { "period": { "interval": 5, "unit": "MINUTES" } },
     *     ...
     *   }
     * }
     * }</pre>
     *
     * After the mapper indexes this doc, {@code parsedDoc().rootDoc()} exposes each JSON leaf as
     * a Lucene field with the JSON pointer path flattened onto a dot-joined field name — that's
     * what {@code extractFieldFromIndexOp} reads via {@code rootDoc.getFields("monitor.type")}.
     */
    private Engine.Index mockMonitorDoc() {
        return mockIndexOp(
            new StringField("monitor.type", "monitor", Field.Store.NO),
            new StringField("monitor.name", "my-monitor", Field.Store.NO),
            new StringField("monitor.monitor_type", "query_level_monitor", Field.Store.NO),
            new StringField("monitor.user.name", "alice", Field.Store.NO),
            new StringField("monitor.user.backend_roles", "engineering", Field.Store.NO),
            new StringField("monitor.enabled", "true", Field.Store.NO)
        );
    }

    /**
     * Same shape as {@link #mockMonitorDoc()}, but for a workflow document. Workflows and
     * monitors share {@code .opendistro-alerting-config}, distinguished only by the wrapper key
     * (and therefore by which {@code <wrapper>.type} Lucene field is present).
     */
    private Engine.Index mockWorkflowDoc() {
        return mockIndexOp(
            new StringField("workflow.type", "workflow", Field.Store.NO),
            new StringField("workflow.name", "my-workflow", Field.Store.NO),
            new StringField("workflow.workflow_type", "composite", Field.Store.NO),
            new StringField("workflow.user.name", "bob", Field.Store.NO),
            new StringField("workflow.user.backend_roles", "ml", Field.Store.NO),
            new StringField("workflow.enabled", "true", Field.Store.NO),
            new StringField("workflow.owner", "alerting", Field.Store.NO)
        );
    }

    private Engine.Index mockIndexOp(IndexableField... fields) {
        Engine.Index indexOp = mock(Engine.Index.class);
        ParsedDocument parsedDoc = mock(ParsedDocument.class);
        org.opensearch.index.mapper.ParseContext.Document rootDoc = new org.opensearch.index.mapper.ParseContext.Document();
        for (IndexableField field : fields) {
            rootDoc.add(field);
        }
        when(indexOp.parsedDoc()).thenReturn(parsedDoc);
        when(parsedDoc.rootDoc()).thenReturn(rootDoc);
        return indexOp;
    }
}
