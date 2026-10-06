/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.dlic.rest.validation;

import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.security.privileges.dlsfls.FieldMaskingDiagnostics;
import org.opensearch.security.support.WildcardMatcher;

import tools.jackson.databind.JsonNode;

/**
 * Best-effort diagnostics against existing mappings, never a condition for saving a role.
 * Inspects at most 100 index/expression pairs and 10,000 properties per role validation.
 * Missing indices, user-dependent patterns, multi-fields, and unknown plugin field types are not diagnosed.
 * Mapping types cannot prove that source values are strings; runtime values are not inspected here.
 */
public final class FieldMaskingMappingValidator {
    private static final Set<String> NON_STRING_TYPES = Set.of(
        "byte",
        "short",
        "integer",
        "long",
        "unsigned_long",
        "half_float",
        "float",
        "double",
        "scaled_float",
        "boolean",
        "date",
        "date_nanos",
        "ip",
        "binary",
        "object",
        "nested",
        "geo_point",
        "geo_shape",
        "knn_vector"
    );

    private FieldMaskingMappingValidator() {}

    public static void inspect(JsonNode role, Metadata metadata) {
        try {
            inspect(
                role,
                metadata,
                finding -> FieldMaskingDiagnostics.warn(finding.index(), finding.field(), finding.type(), "role mapping inspection")
            );
        } catch (RuntimeException e) {
            // Advisory only: incomplete metadata or unresolved patterns must not change role-write behavior.
        }
    }

    record Finding(String index, String field, String type) {
    }

    static void inspect(JsonNode role, Metadata metadata, Consumer<Finding> warning) {
        int[] remaining = { 10000 };
        int indices = 0;
        for (JsonNode permission : role.path("index_permissions")) {
            for (JsonNode expression : permission.path("masked_fields")) {
                WildcardMatcher fieldPattern = WildcardMatcher.from(expression.asText().split("::", 2)[0]);
                for (IndexMetadata index : metadata.indices().values()) {
                    if (++indices > 100 || remaining[0] <= 0) return;
                    if (index.mapping() == null || !matchesIndex(permission, index)) continue;
                    try {
                        inspectProperties(
                            index.mapping().sourceAsMap(),
                            "",
                            fieldPattern,
                            remaining,
                            0,
                            (field, type) -> warning.accept(new Finding(index.getIndex().getName(), field, type))
                        );
                    } catch (RuntimeException e) {
                        // Mapping inspection is advisory; inability to inspect must not reject an otherwise valid role.
                        return;
                    }
                }
            }
        }
    }

    private static boolean matchesIndex(JsonNode permission, IndexMetadata index) {
        for (JsonNode pattern : permission.path("index_patterns")) {
            // Attribute substitution depends on the eventual user; do not guess during role creation.
            if (pattern.asText().contains("${")) continue;
            WildcardMatcher matcher = WildcardMatcher.from(pattern.asText());
            if (matcher.test(index.getIndex().getName()) || index.getAliases().keySet().stream().anyMatch(matcher::test)) return true;
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    static void inspectProperties(
        Map<String, Object> mapping,
        String prefix,
        WildcardMatcher pattern,
        int[] remaining,
        int depth,
        BiConsumer<String, String> warning
    ) {
        if (depth > 50 || remaining[0] <= 0) return;
        Object properties = mapping.get("properties");
        if (!(properties instanceof Map<?, ?>)) return;
        for (Map.Entry<String, Object> entry : ((Map<String, Object>) properties).entrySet()) {
            if (--remaining[0] < 0) return;
            if (!(entry.getValue() instanceof Map<?, ?>)) continue;
            Map<String, Object> definition = (Map<String, Object>) entry.getValue();
            String field = prefix + entry.getKey();
            String type = String.valueOf(definition.getOrDefault("type", "object"));
            if (NON_STRING_TYPES.contains(type) && pattern.test(field)) warning.accept(field, type);
            inspectProperties(definition, field + ".", pattern, remaining, depth + 1, warning);
        }
    }
}
