/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.utils;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.core.common.Strings;

/**
 * Validates user inputs supplied to resource-sharing REST APIs
 */
public final class InputValidation {

    private InputValidation() {}

    public static final int MAX_RESOURCE_ID_LENGTH = 256;
    public static final int MAX_RESOURCE_TYPE_LENGTH = 256;
    public static final int MAX_ACCESS_LEVEL_LENGTH = 256;
    public static final int MAX_PRINCIPAL_LENGTH = 256;
    public static final int MAX_PATH_LENGTH = 256;
    public static final int MAX_INDEX_NAME_LENGTH = 256;
    public static final int MAX_ARRAY_SIZE = 100_000;

    // Alphanumeric + _ - : OR : * - "*" is only allowed as standalone
    private static final Pattern SAFE_VALUE = Pattern.compile("^(\\*|[A-Za-z0-9_:-]+)$");

    /* ---------------------- generic helpers ---------------------- */

    public static void requireNonEmpty(String fieldName, String value) {
        if (Strings.isNullOrEmpty(value)) {
            throw new IllegalArgumentException(fieldName + " must not be null or empty");
        }
    }

    public static void validateMaxLength(String fieldName, String value, int maxLength) {
        if (value.length() > maxLength) {
            throw new IllegalArgumentException(fieldName + " length [" + value.length() + "] exceeds max [" + maxLength + "]");
        }
    }

    public static void validateSafeValue(String fieldName, String value, int maxLength) {
        requireNonEmpty(fieldName, value);
        validateMaxLength(fieldName, value, maxLength);
        if (!SAFE_VALUE.matcher(value).matches()) {
            throw new IllegalArgumentException(fieldName + " contains invalid characters; allowed: A-Z a-z 0-9 _ - :");
        }
    }

    public static void validateArrayEntryCount(String fieldName, int count) {
        if (count > MAX_ARRAY_SIZE) {
            throw new IllegalArgumentException("Array field [" + fieldName + "] exceeds maximum size of " + MAX_ARRAY_SIZE);
        }
    }

    public static void validateResourceId(String resourceId) {
        validateSafeValue("resource_id", resourceId, MAX_RESOURCE_ID_LENGTH);
    }

    public static void validateResourceType(String resourceType, List<String> allowedTypes) {
        validateSafeValue("resource_type", resourceType, MAX_RESOURCE_TYPE_LENGTH);

        if (allowedTypes == null || allowedTypes.isEmpty()) {
            throw new IllegalStateException("No protected resource types configured");
        }

        if (!allowedTypes.contains(resourceType)) {
            throw new IllegalArgumentException("Unsupported resource_type [" + resourceType + "], allowed types: " + allowedTypes);
        }
    }

    public static void validatePrincipalValue(String fieldName, String value) {
        // users / roles / backend_roles entries
        validateSafeValue(fieldName, value, MAX_PRINCIPAL_LENGTH);
    }

    public static void validateAccessLevel(String accessLevel, Set<String> validAccessLevels) {
        requireNonEmpty("access_level", accessLevel);

        validateMaxLength("access_level", accessLevel, MAX_ACCESS_LEVEL_LENGTH);

        if (!SAFE_VALUE.matcher(accessLevel).matches()) {
            throw new IllegalArgumentException("Invalid access_level [" + accessLevel + "]. Allowed characters: A-Z a-z 0-9 _ - :");
        }

        // Check against configured access-level set
        if (validAccessLevels == null || validAccessLevels.isEmpty()) {
            throw new IllegalStateException("No access levels configured.");
        }

        if (!validAccessLevels.contains(accessLevel)) {
            throw new IllegalArgumentException(
                "Invalid access_level [" + accessLevel + "]. Allowed values: " + String.join(", ", validAccessLevels)
            );
        }
    }

    /* -------- JSON helpers for migrate API -------- */

    public static String getRequiredText(JsonNode body, String fieldName, int maxLength) {
        JsonNode node = body.get(fieldName);
        if (node == null || node.isNull() || !node.isTextual()) {
            throw new IllegalArgumentException("Field [" + fieldName + "] is required and must be a non-empty string");
        }
        String value = node.asText();
        requireNonEmpty(fieldName, value);
        validateMaxLength(fieldName, value, maxLength);
        return value;
    }

    public static String getOptionalText(JsonNode body, String fieldName, int maxLength) {
        JsonNode node = body.get(fieldName);
        if (node == null || node.isNull()) {
            return null;
        }
        if (!node.isTextual()) {
            throw new IllegalArgumentException("Field [" + fieldName + "] must be a string when provided");
        }
        String value = node.asText();
        if (value.isEmpty()) {
            return null;
        }
        validateMaxLength(fieldName, value, maxLength);
        return value;
    }

    /* --------- migrate-specific primitives --------- */

    public static void validateJsonPath(String fieldName, String path) {
        requireNonEmpty(fieldName, path);
        validateMaxLength(fieldName, path, MAX_PATH_LENGTH);
        // simple rule: no whitespace anywhere
        if (!path.equals(path.trim()) || path.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException(fieldName + " must not contain whitespace");
        }
    }

    public static void validateSourceIndex(String sourceIndex, Set<String> allowedIndices) {
        requireNonEmpty("source_index", sourceIndex);
        validateMaxLength("source_index", sourceIndex, MAX_INDEX_NAME_LENGTH);
        if (allowedIndices == null || allowedIndices.isEmpty()) {
            throw new IllegalStateException("No protected resource indices configured");
        }
        if (!allowedIndices.contains(sourceIndex)) {
            throw new IllegalArgumentException("Invalid resource index [" + sourceIndex + "]. Allowed indices: " + allowedIndices);
        }
    }

    public static void validateDefaultOwner(String defaultOwner) {
        if (defaultOwner == null) {
            return; // optional
        }
        validatePrincipalValue("default_owner", defaultOwner);
    }

    public static void validateDefaultAccessLevelNode(JsonNode node) {
        if (node == null || node.isNull()) {
            return; // field is optional
        }

        if (!node.isObject()) {
            throw new IllegalArgumentException("default_access_level must be an object");
        }

        if (!node.fieldNames().hasNext()) {
            throw new IllegalArgumentException("default_access_level cannot be empty");
        }

        // Validate values are non-empty strings
        node.fields().forEachRemaining(entry -> {
            JsonNode val = entry.getValue();
            if (!val.isTextual() || val.asText().isEmpty()) {
                throw new IllegalArgumentException("default_access_level for type [" + entry.getKey() + "] must be a non-empty string");
            }
        });
    }
}
