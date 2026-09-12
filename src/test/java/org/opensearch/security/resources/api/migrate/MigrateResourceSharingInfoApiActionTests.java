/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.api.migrate;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.resources.ResourcePluginInfo;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link MigrateResourceSharingInfoApiAction#classifyDocType} and
 * {@link MigrateResourceSharingInfoApiAction#jsonPointer}.
 */
public class MigrateResourceSharingInfoApiActionTests {

    private ObjectMapper mapper;
    private ResourcePluginInfo resourcePluginInfo;

    @Before
    public void setUp() {
        mapper = new ObjectMapper();
        resourcePluginInfo = new ResourcePluginInfo();
    }

    @Test
    public void classifyResolvesFromFirstTypePath() throws Exception {
        JsonNode monitorDoc = mapper.readTree("{ \"monitor\": { \"type\": \"monitor\", \"name\": \"m1\" } }");
        String result = MigrateResourceSharingInfoApiAction.classifyDocType(
            monitorDoc,
            List.of("monitor.type", "workflow.type"),
            Collections.emptyMap(),
            resourcePluginInfo,
            ".alerting-config"
        );
        assertEquals("monitor", result);
    }

    @Test
    public void classifyResolvesFromSecondTypePath() throws Exception {
        JsonNode workflowDoc = mapper.readTree("{ \"workflow\": { \"type\": \"workflow\", \"name\": \"w1\" } }");
        String result = MigrateResourceSharingInfoApiAction.classifyDocType(
            workflowDoc,
            List.of("monitor.type", "workflow.type"),
            Collections.emptyMap(),
            resourcePluginInfo,
            ".alerting-config"
        );
        assertEquals("workflow", result);
    }

    @Test
    public void classifyReturnsNullWhenNoTypePathMatches() throws Exception {
        JsonNode metadataDoc = mapper.readTree("{ \"metadata\": { \"monitor_id\": \"abc123\" } }");
        String result = MigrateResourceSharingInfoApiAction.classifyDocType(
            metadataDoc,
            List.of("monitor.type", "workflow.type"),
            Collections.emptyMap(),
            resourcePluginInfo,
            ".alerting-config"
        );
        assertNull(result);
    }

    @Test
    public void classifyFallsBackToFirstAccessLevelKey() throws Exception {
        // No typePaths declared; typeToDefaultAccessLevel has entries — first key wins.
        JsonNode anyDoc = mapper.readTree("{ \"foo\": \"bar\" }");
        Map<String, String> typeToAccess = new LinkedHashMap<>();
        typeToAccess.put("model_group", "read_only");
        typeToAccess.put("workflow", "read_write");
        String result = MigrateResourceSharingInfoApiAction.classifyDocType(
            anyDoc,
            Collections.emptyList(),
            typeToAccess,
            resourcePluginInfo,
            ".some-index"
        );
        assertEquals("model_group", result);
    }

    @Test
    public void classifyFallsBackToSingleRegisteredType() throws Exception {
        // No typePaths, no access-level map — infer from the sole registered protected type for
        // this index. Mock ResourcePluginInfo to bypass the OpensearchDynamicSetting wiring that a
        // real instance requires.
        ResourcePluginInfo mockInfo = mock(ResourcePluginInfo.class);
        when(mockInfo.currentProtectedTypes()).thenReturn(List.of("model_group"));
        when(mockInfo.indexByType("model_group")).thenReturn(".ml-model-groups");

        JsonNode anyDoc = mapper.readTree("{ \"whatever\": {} }");
        String result = MigrateResourceSharingInfoApiAction.classifyDocType(
            anyDoc,
            Collections.emptyList(),
            Collections.emptyMap(),
            mockInfo,
            ".ml-model-groups"
        );
        assertEquals("model_group", result);
    }

    @Test
    public void classifyReturnsNullWhenNothingResolvableAndIndexUnknown() throws Exception {
        ResourcePluginInfo mockInfo = mock(ResourcePluginInfo.class);
        when(mockInfo.currentProtectedTypes()).thenReturn(Collections.emptyList());

        JsonNode anyDoc = mapper.readTree("{ \"whatever\": {} }");
        String result = MigrateResourceSharingInfoApiAction.classifyDocType(
            anyDoc,
            Collections.emptyList(),
            Collections.emptyMap(),
            mockInfo,
            ".not-registered"
        );
        assertNull(result);
    }

    @Test
    public void extractWorkspacesReadsAllArrayValues() throws Exception {
        JsonNode doc = mapper.readTree("{ \"workspaces\": [\"ws-a\", \"ws-b\", \"ws-c\"] }");
        assertEquals(java.util.Set.of("ws-a", "ws-b", "ws-c"), MigrateResourceSharingInfoApiAction.extractWorkspaces(doc, "workspaces"));
    }

    @Test
    public void extractWorkspacesToleratesSingleScalarValue() throws Exception {
        JsonNode doc = mapper.readTree("{ \"workspaces\": \"ws-only\" }");
        assertEquals(java.util.Set.of("ws-only"), MigrateResourceSharingInfoApiAction.extractWorkspaces(doc, "workspaces"));
    }

    @Test
    public void extractWorkspacesReturnsEmptyWhenFieldAbsent() throws Exception {
        JsonNode doc = mapper.readTree("{ \"other\": 1 }");
        assertEquals(Collections.emptySet(), MigrateResourceSharingInfoApiAction.extractWorkspaces(doc, "workspaces"));
    }

    @Test
    public void extractWorkspacesIgnoresBlankIdsAndNullField() throws Exception {
        JsonNode doc = mapper.readTree("{ \"workspaces\": [\"ws-a\", \"\"] }");
        assertEquals(java.util.Set.of("ws-a"), MigrateResourceSharingInfoApiAction.extractWorkspaces(doc, "workspaces"));
        assertEquals(Collections.emptySet(), MigrateResourceSharingInfoApiAction.extractWorkspaces(doc, null));
    }

    @Test
    public void extractWorkspacesSupportsDotNotationPath() throws Exception {
        JsonNode doc = mapper.readTree("{ \"meta\": { \"workspaces\": [\"ws-a\"] } }");
        assertEquals(java.util.Set.of("ws-a"), MigrateResourceSharingInfoApiAction.extractWorkspaces(doc, "meta.workspaces"));
    }

    @Test
    public void jsonPointerAcceptsDotNotation() {
        assertEquals("/monitor/user/name", MigrateResourceSharingInfoApiAction.jsonPointer("monitor.user.name"));
    }

    @Test
    public void jsonPointerPreservesLeadingSlash() {
        assertEquals("/monitor/user/name", MigrateResourceSharingInfoApiAction.jsonPointer("/monitor/user/name"));
    }

    @Test
    public void classifyNotificationConfigFallsBackToSingleAccessLevelKey() throws Exception {
        // A single-provider index with no typeField (e.g. notifications' notification_config) is
        // classified by the sole default_access_level key, so the doc is migrated rather than skipped.
        // Uses a faithful `.opensearch-notifications-config` _source (NotificationConfigDoc.toXContent:
        // metadata + config, no envelope) with the real NotificationConstants tag names.
        JsonNode notifDoc = mapper.readTree(
            "{ \"metadata\": { \"last_updated_time_ms\": 1735689600000, \"created_time_ms\": 1735689600000,"
                + " \"access\": [\"role_a\", \"role_b\"] },"
                + " \"config\": { \"name\": \"channel-1\", \"config_type\": \"slack\", \"is_enabled\": true } }"
        );
        String result = MigrateResourceSharingInfoApiAction.classifyDocType(
            notifDoc,
            Collections.emptyList(),
            Collections.singletonMap("notification_config", "notifications_read_write"),
            resourcePluginInfo,
            ".opensearch-notifications-config"
        );
        assertEquals("notification_config", result);
    }

    @Test
    public void nonResolvingUsernamePathYieldsNoOwnerSoMigrationUsesDefaultOwner() throws Exception {
        // Notification config docs have no owner name. The migrate call must still pass a valid,
        // non-empty username_path (an empty "" is rejected by PATH_VALIDATOR#requireNonEmpty), so it
        // is pointed at a path that does not exist on the doc. It resolves to no value (null) and
        // createNewSharingRecords falls back to default_owner, while backend_roles_path
        // "/metadata/access" still yields the legacy access list to share with.
        JsonNode notifDoc = mapper.readTree(
            "{ \"metadata\": { \"last_updated_time_ms\": 1735689600000, \"created_time_ms\": 1735689600000,"
                + " \"access\": [\"role_a\", \"role_b\"] },"
                + " \"config\": { \"name\": \"channel-1\", \"config_type\": \"slack\", \"is_enabled\": true } }"
        );

        // An empty username_path is rejected before extraction, so it cannot be used in the doc example.
        assertThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.validatePath("username_path", "", RequestContentValidator.MAX_STRING_LENGTH)
        );

        // A valid, non-resolving path passes validation and yields no owner (-> default_owner).
        RequestContentValidator.validatePath("username_path", "/metadata/owner", RequestContentValidator.MAX_STRING_LENGTH);
        String username = notifDoc.at(MigrateResourceSharingInfoApiAction.jsonPointer("/metadata/owner")).asText(null);
        assertNull(username);

        JsonNode backendRoles = notifDoc.at(MigrateResourceSharingInfoApiAction.jsonPointer("/metadata/access"));
        assertEquals(2, backendRoles.size());
        assertEquals("role_a", backendRoles.get(0).asText());
        assertEquals("role_b", backendRoles.get(1).asText());
    }

}
