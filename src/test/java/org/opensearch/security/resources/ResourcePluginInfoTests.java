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

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.mapper.ParsedDocument;
import org.opensearch.security.resources.settings.ResourceSharingProtectedResourcesSetting;
import org.opensearch.security.setting.OpensearchDynamicSetting;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
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
    public void testProviderDeclaresTheValueItsDocumentsHold() {
        registerAlertingProviders();

        assertEquals("alerting-workflow", resourcePluginInfo.getResourceTypeForIndexOp(".alerting-config", mockWorkflowDoc()));
        assertEquals("monitor", resourcePluginInfo.getResourceTypeForIndexOp(".alerting-config", mockMonitorDoc()));
    }

    @Test
    public void testValueOtherThanTheDeclaredOneIsNotThatType() {
        // Without the declared value, the default is the type name, which workflow documents do not hold
        registerProviders("monitor", "monitor.type", "alerting-workflow", "workflow.type", ".alerting-config");

        assertNull(resourcePluginInfo.getResourceTypeForIndexOp(".alerting-config", mockWorkflowDoc()));
    }

    @Test
    public void testSharedFieldResolvesByValue() {
        // The sample plugin's shape: three types on one index, one shared discriminator field
        registerProviders(List.of("sample-resource", "sample-resource-group", "workspace"), ".sample-index", "resource_type");

        assertEquals(
            "sample-resource-group",
            resourcePluginInfo.getResourceTypeForIndexOp(".sample-index", typedDoc("sample-resource-group"))
        );
        assertEquals("workspace", resourcePluginInfo.getResourceTypeForIndexOp(".sample-index", typedDoc("workspace")));
        // A value no provider declares is not a resource, even though the field is present
        assertNull(resourcePluginInfo.getResourceTypeForIndexOp(".sample-index", typedDoc("something-else")));
    }

    @Test
    public void testClassificationDoesNotDependOnProtection() {
        // Classification does not depend on protection: a group document stays a group when only resources are protected
        registerProviders(List.of("sample-resource", "sample-resource-group"), ".sample-index", "resource_type");
        resourcePluginInfo.updateProtectedTypes(List.of("sample-resource"));

        assertEquals(
            "sample-resource-group",
            resourcePluginInfo.getResourceTypeForIndexOp(".sample-index", typedDoc("sample-resource-group"))
        );
    }

    @Test
    public void testDocumentWithoutTheFieldIsNotAResource() {
        // ml-commons' shape: model chunks share the model index but carry no resource_type
        registerProviders(List.of("ml-model"), ".plugins-ml-model", "resource_type");

        assertNull(
            resourcePluginInfo.getResourceTypeForIndexOp(
                ".plugins-ml-model",
                mockIndexOp(new StringField("chunk_number", "3", Field.Store.NO))
            )
        );
        assertEquals("ml-model", resourcePluginInfo.getResourceTypeForIndexOp(".plugins-ml-model", typedDoc("ml-model")));
    }

    @Test
    public void testDocumentMatchingTwoProvidersIsNotAResource() {
        registerAlertingProviders();

        Engine.Index both = mockIndexOp(
            new StringField("monitor.type", "monitor", Field.Store.NO),
            new StringField("workflow.type", "workflow", Field.Store.NO)
        );
        assertNull(resourcePluginInfo.getResourceTypeForIndexOp(".alerting-config", both));
    }

    @Test
    public void testRejectsTwoUntypedTypesOnOneIndex() {
        OpenSearchSecurityException ex = assertThrows(
            OpenSearchSecurityException.class,
            () -> registerExtension(makeProvider("a", ".shared-index", null), makeProvider("b", ".shared-index", null))
        );
        assertTrue(ex.getMessage().contains("both declare no typeField"));
    }

    @Test
    public void testRejectsATypeFieldWithoutAValue() {
        OpenSearchSecurityException ex = assertThrows(
            OpenSearchSecurityException.class,
            () -> registerExtension(makeProvider("a", ".some-index", "kind", null))
        );
        assertTrue(ex.getMessage().contains("declares typeField [kind] but no typeFieldValue"));
    }

    @Test
    public void testRejectsTwoTypesIdentifiedTheSameWay() {
        OpenSearchSecurityException ex = assertThrows(
            OpenSearchSecurityException.class,
            () -> registerExtension(makeProvider("a", ".shared-index", "kind", "same"), makeProvider("b", ".shared-index", "kind", "same"))
        );
        assertTrue(ex.getMessage().contains("are both identified by [kind] holding [same]"));
    }

    @Test
    public void testUntypedProviderClaimsOnlyUnclaimedDocuments() {
        // The names put the untyped provider first in the registry's HashMap order, so a first-match rule would misclassify
        registerProviders("b-untyped", null, "a-typed", "a.type", ".mixed-index");

        assertEquals(
            "a-typed",
            resourcePluginInfo.getResourceTypeForIndexOp(".mixed-index", mockIndexOp(new StringField("a.type", "a-typed", Field.Store.NO)))
        );
        assertEquals(
            "b-untyped",
            resourcePluginInfo.getResourceTypeForIndexOp(".mixed-index", mockIndexOp(new StringField("other", "x", Field.Store.NO)))
        );
    }

    @Test
    public void testTypeMatchesSplitByProtection() {
        registerAlertingProviders();
        resourcePluginInfo.setProtectedTypesSetting(protectedTypes(List.of("alerting-workflow")));

        ResourcePluginInfo.TypeMatches matches = resourcePluginInfo.typeMatches(".alerting-config");
        assertEquals(List.of(new ResourcePluginInfo.TypeMatch("workflow.type", "workflow")), matches.protectedTypes());
        assertEquals(List.of(new ResourcePluginInfo.TypeMatch("monitor.type", "monitor")), matches.unprotectedTypes());
    }

    @Test
    public void testTypeMatchesOnASharedFieldAreByValue() {
        registerProviders(List.of("sample-resource", "sample-resource-group"), ".sample-index", "resource_type");
        resourcePluginInfo.setProtectedTypesSetting(protectedTypes(List.of("sample-resource")));

        ResourcePluginInfo.TypeMatches matches = resourcePluginInfo.typeMatches(".sample-index");
        assertEquals(List.of(new ResourcePluginInfo.TypeMatch("resource_type", "sample-resource")), matches.protectedTypes());
        assertEquals(List.of(new ResourcePluginInfo.TypeMatch("resource_type", "sample-resource-group")), matches.unprotectedTypes());
    }

    @Test
    public void testNoUnprotectedTypeMeansNoExemption() {
        // The common case: every type on the index is protected, so the DLS clause gains nothing
        registerAlertingProviders();
        resourcePluginInfo.setProtectedTypesSetting(protectedTypes(List.of("monitor", "alerting-workflow")));

        assertTrue(resourcePluginInfo.typeMatches(".alerting-config").unprotectedTypes().isEmpty());
    }

    private static OpensearchDynamicSetting<List<String>> protectedTypes(List<String> types) {
        return new OpensearchDynamicSetting<>(ResourceSharingProtectedResourcesSetting.PROTECTED_TYPES, types) {
        };
    }

    /** A document holding {@code value} in {@code resource_type}. */
    private Engine.Index typedDoc(String value) {
        return mockIndexOp(new StringField("resource_type", value, Field.Store.NO));
    }

    @Test
    public void testUnknownIndexReturnsNull() {
        registerProviders(List.of("monitor"), ".alerting-config", "monitor.type");
        resourcePluginInfo.updateProtectedTypes(List.of("monitor"));

        Engine.Index indexOp = mockMonitorDoc();
        String result = resourcePluginInfo.getResourceTypeForIndexOp(".some-other-index", indexOp);
        assertNull(result);
    }

    @Test
    public void testRejectsConflictingWorkspacesFieldsOnSameIndex() {
        // Two providers sharing an index but declaring different workspaces fields is a misconfiguration: DLS can only
        // filter one field per index. Registration must reject it rather than silently pick one.
        ResourceSharingExtension extension = new ResourceSharingExtension() {
            @Override
            public Set<ResourceProvider> getResourceProviders() {
                var providers = new java.util.LinkedHashSet<ResourceProvider>();
                providers.add(workspacesProvider("a", ".shared-index", "workspaces"));
                providers.add(workspacesProvider("b", ".shared-index", "ws"));
                return providers;
            }

            @Override
            public void assignResourceSharingClient(ResourceSharingClient client) {}
        };

        OpenSearchSecurityException ex = assertThrows(
            OpenSearchSecurityException.class,
            () -> resourcePluginInfo.setResourceSharingExtensions(Set.of(extension))
        );
        assertTrue(ex.getMessage().contains("Conflicting workspaces fields"));
    }

    @Test
    public void testAllowsMatchingWorkspacesFieldsOnSameIndex() {
        // Providers sharing an index that agree on the workspaces field (or opt out with null) are accepted.
        ResourceSharingExtension extension = new ResourceSharingExtension() {
            @Override
            public Set<ResourceProvider> getResourceProviders() {
                var providers = new java.util.LinkedHashSet<ResourceProvider>();
                providers.add(workspacesProvider("a", ".shared-index", "workspaces"));
                providers.add(workspacesProvider("b", ".shared-index", "workspaces"));
                providers.add(workspacesProvider("c", ".shared-index", null));
                return providers;
            }

            @Override
            public void assignResourceSharingClient(ResourceSharingClient client) {}
        };

        resourcePluginInfo.setResourceSharingExtensions(Set.of(extension));
        resourcePluginInfo.updateProtectedTypes(Arrays.asList("a", "b", "c"));
        assertEquals("workspaces", resourcePluginInfo.workspacesFieldForIndex(".shared-index"));
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────────

    private ResourceProvider workspacesProvider(String type, String index, String field) {
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
                return "resource_type";
            }

            @Override
            public String workspacesField() {
                return field;
            }
        };
    }

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

    /** alerting's two providers as alerting declares them: workflow documents hold "workflow", not the type name. */
    private void registerAlertingProviders() {
        registerExtension(
            makeProvider("monitor", ".alerting-config", "monitor.type"),
            makeProvider("alerting-workflow", ".alerting-config", "workflow.type", "workflow")
        );
    }

    private void registerExtension(ResourceProvider... providers) {
        resourcePluginInfo.setResourceSharingExtensions(Set.of(new ResourceSharingExtension() {
            @Override
            public Set<ResourceProvider> getResourceProviders() {
                return new java.util.LinkedHashSet<>(List.of(providers));
            }

            @Override
            public void assignResourceSharingClient(ResourceSharingClient client) {}
        }));
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
        return makeProvider(type, index, typeField, type);
    }

    private ResourceProvider makeProvider(String type, String index, String typeField, String typeFieldValue) {
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

    // ---------- extractMultiValuedFieldFromIndexOp --------------------------------------------------

    @Test
    public void extractMultiValued_collectsAllValuesOfAField() {
        Engine.Index indexOp = mockIndexOp(
            new StringField("workspaces", "ws-a", Field.Store.NO),
            new StringField("workspaces", "ws-b", Field.Store.NO),
            new StringField("name", "n", Field.Store.NO)
        );
        assertEquals(Set.of("ws-a", "ws-b"), ResourcePluginInfo.extractMultiValuedFieldFromIndexOp("workspaces", indexOp));
    }

    @Test
    public void extractMultiValued_emptyWhenFieldAbsent() {
        Engine.Index indexOp = mockIndexOp(new StringField("name", "n", Field.Store.NO));
        assertTrue(ResourcePluginInfo.extractMultiValuedFieldFromIndexOp("workspaces", indexOp).isEmpty());
    }

    // ---------- workspacesFieldForIndex ------------------------------------------------------------

    @Test
    public void workspacesFieldForIndex_returnsDeclaredFieldOrNull() {
        ResourceSharingExtension ext = new ResourceSharingExtension() {
            @Override
            public Set<ResourceProvider> getResourceProviders() {
                return Set.of(new ResourceProvider() {
                    @Override
                    public String resourceType() {
                        return "dashboard";
                    }

                    @Override
                    public String resourceIndexName() {
                        return ".kibana";
                    }

                    @Override
                    public String workspacesField() {
                        return "ws";
                    }
                });
            }

            @Override
            public void assignResourceSharingClient(ResourceSharingClient client) {}
        };
        resourcePluginInfo.setResourceSharingExtensions(Set.of(ext));

        assertEquals("ws", resourcePluginInfo.workspacesFieldForIndex(".kibana"));
        assertNull(resourcePluginInfo.workspacesFieldForIndex(".other-index"));
    }

    // ---------- resolveWorkspacesForUser (SPI seam) --------------------------------------------------

    @Test
    public void resolveWorkspaces_returnsEmptyWhenNoExtensionsRegistered() {
        // No extensions -> nothing to resolve; must not throw and must not add workspace principals.
        Set<String> result = resourcePluginInfo.resolveWorkspacesForUser(mockUser("alice", Set.of("r1"), Set.of()));
        assertEquals(java.util.Collections.emptySet(), result);
    }

    @Test
    public void resolveWorkspaces_returnsEmptyWhenExtensionUsesDefaultImplementation() {
        // An extension that does not override the resolver -> empty (default returns Collections.emptySet()).
        // This is what preserves BWC for all existing plugins.
        registerProviders(List.of("monitor"), ".alerting-config", null);
        Set<String> result = resourcePluginInfo.resolveWorkspacesForUser(mockUser("alice", Set.of("r1"), Set.of()));
        assertEquals(java.util.Collections.emptySet(), result);
    }

    @Test
    public void resolveWorkspaces_aggregatesAcrossExtensions() {
        // Two extensions both override; the aggregator unions their contributions.
        ResourceSharingExtension a = extensionWithResolver((u, sr, br) -> Set.of("ws-a1", "ws-a2"));
        ResourceSharingExtension b = extensionWithResolver((u, sr, br) -> Set.of("ws-a2", "ws-b1"));
        resourcePluginInfo.setResourceSharingExtensions(Set.of(a, b));

        Set<String> result = resourcePluginInfo.resolveWorkspacesForUser(mockUser("alice", Set.of("r1"), Set.of()));
        assertEquals(Set.of("ws-a1", "ws-a2", "ws-b1"), result);
    }

    @Test
    public void resolveWorkspaces_forwardsUserFieldsToResolver() {
        // Extensions receive the user's name + role sets so a trusted server-set resolver can map on them.
        java.util.concurrent.atomic.AtomicReference<String> capturedName = new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicReference<Set<String>> capturedSecRoles = new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicReference<Set<String>> capturedBackendRoles = new java.util.concurrent.atomic.AtomicReference<>();
        ResourceSharingExtension ext = extensionWithResolver((u, sr, br) -> {
            capturedName.set(u);
            capturedSecRoles.set(sr);
            capturedBackendRoles.set(br);
            return Set.of("ws-x");
        });
        resourcePluginInfo.setResourceSharingExtensions(Set.of(ext));

        resourcePluginInfo.resolveWorkspacesForUser(mockUser("bob", Set.of("analyst"), Set.of("ldap-eng")));

        assertEquals("bob", capturedName.get());
        assertEquals(Set.of("analyst"), capturedSecRoles.get());
        assertEquals(Set.of("ldap-eng"), capturedBackendRoles.get());
    }

    @Test
    public void resolveWorkspaces_toleratesNullOrEmptyContributions() {
        // An extension returning null (contract-violating but reachable) must not NPE the aggregation.
        ResourceSharingExtension nullContrib = extensionWithResolver((u, sr, br) -> null);
        ResourceSharingExtension emptyContrib = extensionWithResolver((u, sr, br) -> java.util.Collections.emptySet());
        ResourceSharingExtension realContrib = extensionWithResolver((u, sr, br) -> Set.of("ws-real"));
        resourcePluginInfo.setResourceSharingExtensions(Set.of(nullContrib, emptyContrib, realContrib));

        Set<String> result = resourcePluginInfo.resolveWorkspacesForUser(mockUser("alice", Set.of(), Set.of()));
        assertEquals(Set.of("ws-real"), result);
    }

    @FunctionalInterface
    private interface WorkspaceResolver {
        Set<String> resolve(String username, Set<String> securityRoles, Set<String> backendRoles);
    }

    private ResourceSharingExtension extensionWithResolver(WorkspaceResolver resolver) {
        return new ResourceSharingExtension() {
            @Override
            public Set<ResourceProvider> getResourceProviders() {
                return Set.of();
            }

            @Override
            public void assignResourceSharingClient(ResourceSharingClient client) {}

            @Override
            public Set<String> resolveWorkspacesForUser(String username, Set<String> securityRoles, Set<String> backendRoles) {
                return resolver.resolve(username, securityRoles, backendRoles);
            }
        };
    }

    private org.opensearch.security.user.User mockUser(String name, Set<String> securityRoles, Set<String> backendRoles) {
        // Use a real User (not a mock) — User is a plain class and Mockito default-mocks trip on it.
        return new org.opensearch.security.user.User(name).withRoles(backendRoles).withSecurityRoles(securityRoles);
    }

    // ---------- fixtures --------------------------------------------------------------------------

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
