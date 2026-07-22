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

        Engine.Index indexOp = mockIndexOp(new StringField("monitor.type", "monitor", Field.Store.NO));
        String result = resourcePluginInfo.getResourceTypeForIndexOp(".alerting-config", indexOp);
        assertEquals("monitor", result);
    }

    @Test
    public void testMultipleProvidersFirstProviderResolves() {
        registerProviders("monitor", "monitor.type", "workflow", "workflow.type", ".alerting-config");
        resourcePluginInfo.updateProtectedTypes(Arrays.asList("monitor", "workflow"));

        Engine.Index indexOp = mockIndexOp(new StringField("monitor.type", "monitor", Field.Store.NO));
        String result = resourcePluginInfo.getResourceTypeForIndexOp(".alerting-config", indexOp);
        assertEquals("monitor", result);
    }

    @Test
    public void testMultipleProvidersSecondProviderResolves() {
        registerProviders("monitor", "monitor.type", "workflow", "workflow.type", ".alerting-config");
        resourcePluginInfo.updateProtectedTypes(Arrays.asList("monitor", "workflow"));

        // Only workflow.type present — monitor.type returns null
        Engine.Index indexOp = mockIndexOp(new StringField("workflow.type", "workflow", Field.Store.NO));
        String result = resourcePluginInfo.getResourceTypeForIndexOp(".alerting-config", indexOp);
        assertEquals("workflow", result);
    }

    @Test
    public void testMultipleProvidersNeitherResolves() {
        registerProviders("monitor", "monitor.type", "workflow", "workflow.type", ".alerting-config");
        resourcePluginInfo.updateProtectedTypes(Arrays.asList("monitor", "workflow"));

        Engine.Index indexOp = mockIndexOp(); // no type fields
        String result = resourcePluginInfo.getResourceTypeForIndexOp(".alerting-config", indexOp);
        assertNull(result);
    }

    @Test
    public void testUnknownIndexReturnsNull() {
        registerProviders(List.of("monitor"), ".alerting-config", "monitor.type");
        resourcePluginInfo.updateProtectedTypes(List.of("monitor"));

        Engine.Index indexOp = mockIndexOp(new StringField("monitor.type", "monitor", Field.Store.NO));
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
            public void assignResourceSharingClient(ResourceSharingClient client) {
            }
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
            public void assignResourceSharingClient(ResourceSharingClient client) {
            }
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

    private Engine.Index mockIndexOp(IndexableField... fields) {
        Engine.Index indexOp = mock(Engine.Index.class);
        ParsedDocument parsedDoc = mock(ParsedDocument.class);
        org.opensearch.index.mapper.ParseContext.Document rootDoc =
            new org.opensearch.index.mapper.ParseContext.Document();
        for (IndexableField field : fields) {
            rootDoc.add(field);
        }
        when(indexOp.parsedDoc()).thenReturn(parsedDoc);
        when(parsedDoc.rootDoc()).thenReturn(rootDoc);
        return indexOp;
    }
}
