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

import org.opensearch.security.resources.ResourcePluginInfo;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
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
    public void jsonPointerAcceptsDotNotation() {
        assertEquals("/monitor/user/name", MigrateResourceSharingInfoApiAction.jsonPointer("monitor.user.name"));
    }

    @Test
    public void jsonPointerPreservesLeadingSlash() {
        assertEquals("/monitor/user/name", MigrateResourceSharingInfoApiAction.jsonPointer("/monitor/user/name"));
    }

}
