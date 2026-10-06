/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.dlic.rest.validation;

import java.util.ArrayList;
import java.util.Map;

import org.apache.lucene.tests.util.LuceneTestCase;

import org.opensearch.Version;
import org.opensearch.cluster.metadata.AliasMetadata;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.support.WildcardMatcher;

public class FieldMaskingMappingValidatorTests extends LuceneTestCase {
    public void testMixedMappingsAndAliases() throws Exception {
        Metadata.Builder metadata = Metadata.builder();
        for (String type : new String[] { "keyword", "long" }) {
            metadata.put(
                IndexMetadata.builder("test-" + type)
                    .settings(Settings.builder().put(IndexMetadata.SETTING_VERSION_CREATED, Version.CURRENT))
                    .numberOfShards(1)
                    .numberOfReplicas(0)
                    .putAlias(AliasMetadata.builder("shared-alias"))
                    .putMapping(new MappingMetadata("_doc", Map.of("properties", Map.of("value", Map.of("type", type)))))
            );
        }
        for (String pattern : new String[] { "test-*", "shared-alias" }) {
            var role = DefaultObjectMapper.objectMapper()
                .readTree("{\"index_permissions\":[{\"index_patterns\":[\"" + pattern + "\"],\"masked_fields\":[\"value\"]}]}");
            var warnings = new ArrayList<FieldMaskingMappingValidator.Finding>();
            FieldMaskingMappingValidator.inspect(role, metadata.build(), warnings::add);
            assertEquals(java.util.List.of(new FieldMaskingMappingValidator.Finding("test-long", "value", "long")), warnings);
        }
    }

    public void testMappedTypesAndNestedFields() {
        Map<String, Object> mapping = Map.of(
            "properties",
            Map.of(
                "text",
                Map.of("type", "text"),
                "keyword",
                Map.of("type", "keyword"),
                "number",
                Map.of("type", "long"),
                "object",
                Map.of("properties", Map.of("flag", Map.of("type", "boolean")))
            )
        );
        var warnings = new ArrayList<String>();
        FieldMaskingMappingValidator.inspectProperties(
            mapping,
            "",
            WildcardMatcher.from("*"),
            new int[] { 100 },
            0,
            (field, type) -> warnings.add(field + ":" + type)
        );
        assertEquals(3, warnings.size());
        assertTrue(warnings.contains("number:long"));
        assertTrue(warnings.contains("object:object"));
        assertTrue(warnings.contains("object.flag:boolean"));
    }

    public void testInspectionIsBounded() {
        var warnings = new ArrayList<String>();
        FieldMaskingMappingValidator.inspectProperties(
            Map.of("properties", Map.of("number", Map.of("type", "long"))),
            "",
            WildcardMatcher.from("*"),
            new int[] { 0 },
            0,
            (field, type) -> warnings.add(field)
        );
        assertTrue(warnings.isEmpty());
    }

    public void testFutureIndicesAreAllowed() {
        var role = DefaultObjectMapper.objectMapper()
            .readTree("{\"index_permissions\":[{\"index_patterns\":[\"future-*\"],\"masked_fields\":[\"number\"]}]}");
        FieldMaskingMappingValidator.inspect(role, Metadata.EMPTY_METADATA);
    }
}
