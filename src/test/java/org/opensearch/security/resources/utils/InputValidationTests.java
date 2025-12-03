/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class InputValidationTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /* ---------------------- helpers ---------------------- */

    private static String repeat(char c, int count) {
        char[] arr = new char[count];
        Arrays.fill(arr, c);
        return new String(arr);
    }

    private static <T extends Throwable> void expectThrows(Class<T> expected, Runnable runnable) {
        try {
            runnable.run();
            fail("Expected exception of type " + expected.getName());
        } catch (Throwable t) {
            assertTrue(
                "Unexpected exception type. Expected " + expected.getName() + " but got " + t.getClass().getName(),
                expected.isInstance(t)
            );
            @SuppressWarnings("unchecked")
            T cast = (T) t;
        }
    }

    private static JsonNode json(String s) throws Exception {
        return MAPPER.readTree(s);
    }

    /* ---------------------- requireNonEmpty ---------------------- */

    @Test
    public void testRequireNonEmptyAcceptsNonEmpty() {
        InputValidation.requireNonEmpty("field", "value");
    }

    @Test
    public void testRequireNonEmptyRejectsNull() {
        expectThrows(IllegalArgumentException.class, () -> InputValidation.requireNonEmpty("field", null));
    }

    @Test
    public void testRequireNonEmptyRejectsEmpty() {
        expectThrows(IllegalArgumentException.class, () -> InputValidation.requireNonEmpty("field", ""));
    }

    /* ---------------------- validateMaxLength ---------------------- */

    @Test
    public void testValidateMaxLengthAtBoundary() {
        String value = repeat('a', 5);
        InputValidation.validateMaxLength("field", value, 5);
    }

    @Test
    public void testValidateMaxLengthRejectsOverLimit() {
        String value = repeat('a', 6);
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateMaxLength("field", value, 5));
    }

    /* ---------------------- validateSafeValue ---------------------- */

    @Test
    public void testValidateSafeValueAcceptsAllowedCharacters() {
        String value = "Abc123_-:xyz";
        InputValidation.validateSafeValue("field", value, 50);
    }

    @Test
    public void testValidateSafeValueRejectsInvalidCharacters() {
        String value = "bad value$"; // space + $
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateSafeValue("field", value, 50));
    }

    @Test
    public void testValidateSafeValueRejectsTooLong() {
        String value = repeat('a', 11);
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateSafeValue("field", value, 10));
    }

    /* ---------------------- validateArrayEntryCount ---------------------- */

    @Test
    public void testValidateArrayEntryCountAtMaxBoundary() {
        InputValidation.validateArrayEntryCount("field", InputValidation.MAX_ARRAY_SIZE);
    }

    @Test
    public void testValidateArrayEntryCountRejectsAboveMax() {
        int overMax = InputValidation.MAX_ARRAY_SIZE + 1;
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateArrayEntryCount("field", overMax));
    }

    /* ---------------------- validateResourceId ---------------------- */

    @Test
    public void testValidateResourceIdAcceptsValidId() {
        String id = "resource_123-ABC:xyz";
        InputValidation.validateResourceId(id);
    }

    @Test
    public void testValidateResourceIdRejectsInvalidCharacters() {
        String id = "invalid id!"; // space + !
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateResourceId(id));
    }

    @Test
    public void testValidateResourceIdRejectsTooLong() {
        String id = repeat('a', InputValidation.MAX_RESOURCE_ID_LENGTH + 1);
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateResourceId(id));
    }

    /* ---------------------- validateResourceType ---------------------- */

    @Test
    public void testValidateResourceTypeAcceptsValidTypeInAllowedList() {
        List<String> allowedTypes = Arrays.asList("anomaly-detector", "forecaster", "ml-model");
        InputValidation.validateResourceType("anomaly-detector", allowedTypes);
    }

    @Test
    public void testValidateResourceTypeRejectsInvalidCharacters() {
        List<String> allowedTypes = List.of("anomaly-detector");
        String resourceType = "anomaly detector"; // contains space
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateResourceType(resourceType, allowedTypes));
    }

    @Test
    public void testValidateResourceTypeRejectsWhenNoAllowedTypesConfiguredNull() {
        expectThrows(IllegalStateException.class, () -> InputValidation.validateResourceType("anomaly-detector", null));
    }

    @Test
    public void testValidateResourceTypeRejectsWhenNoAllowedTypesConfiguredEmpty() {
        expectThrows(IllegalStateException.class, () -> InputValidation.validateResourceType("anomaly-detector", Collections.emptyList()));
    }

    @Test
    public void testValidateResourceTypeRejectsWhenTypeNotInAllowedList() {
        List<String> allowedTypes = Arrays.asList("anomaly-detector", "forecaster");
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateResourceType("ml-model", allowedTypes));
    }

    /* ---------------------- validatePrincipalValue ---------------------- */

    @Test
    public void testValidatePrincipalValueAcceptsValidPrincipal() {
        InputValidation.validatePrincipalValue("users", "user_123-role:1");
    }

    @Test
    public void testValidatePrincipalValueRejectsInvalidCharacters() {
        expectThrows(
            IllegalArgumentException.class,
            () -> InputValidation.validatePrincipalValue("users", "user name") // space
        );
    }

    @Test
    public void testValidatePrincipalValueRejectsTooLong() {
        String principal = repeat('u', InputValidation.MAX_PRINCIPAL_LENGTH + 1);
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validatePrincipalValue("users", principal));
    }

    /* ---------------------- validateAccessLevel ---------------------- */

    @Test
    public void testValidateAccessLevelAcceptsValidValueInSet() {
        Set<String> allowed = new HashSet<>(Arrays.asList("rd_read_only", "rd_write", "forecast:read", "forecast:write"));

        InputValidation.validateAccessLevel("rd_read_only", allowed);
        InputValidation.validateAccessLevel("forecast:write", allowed);
    }

    @Test
    public void testValidateAccessLevelRejectsNullAccessLevel() {
        Set<String> allowed = new HashSet<>(List.of("rd_read_only"));
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateAccessLevel(null, allowed));
    }

    @Test
    public void testValidateAccessLevelRejectsEmptyAccessLevel() {
        Set<String> allowed = new HashSet<>(List.of("rd_read_only"));
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateAccessLevel("", allowed));
    }

    @Test
    public void testValidateAccessLevelRejectsTooLongAccessLevel() {
        Set<String> allowed = new HashSet<>(List.of("rd_read_only"));
        String longAccess = repeat('a', InputValidation.MAX_ACCESS_LEVEL_LENGTH + 1);
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateAccessLevel(longAccess, allowed));
    }

    @Test
    public void testValidateAccessLevelRejectsInvalidCharacters() {
        Set<String> allowed = new HashSet<>(List.of("rd_read_only"));
        String invalid = "rd read"; // space
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateAccessLevel(invalid, allowed));
    }

    @Test
    public void testValidateAccessLevelRejectsWhenNoAccessLevelsConfiguredNull() {
        expectThrows(IllegalStateException.class, () -> InputValidation.validateAccessLevel("rd_read_only", null));
    }

    @Test
    public void testValidateAccessLevelRejectsWhenNoAccessLevelsConfiguredEmpty() {
        expectThrows(IllegalStateException.class, () -> InputValidation.validateAccessLevel("rd_read_only", Collections.emptySet()));
    }

    @Test
    public void testValidateAccessLevelRejectsWhenNotInAllowedSet() {
        Set<String> allowed = new HashSet<>(Arrays.asList("rd_read_only", "rd_write"));
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateAccessLevel("forecast:read", allowed));
    }

    @Test
    public void testGetRequiredTextReturnsValueWhenPresent() throws Exception {
        JsonNode body = json("{\"source_index\":\"index-1\"}");

        String result = InputValidation.getRequiredText(body, "source_index", InputValidation.MAX_INDEX_NAME_LENGTH);

        assertEquals("index-1", result);
    }

    @Test
    public void testGetRequiredTextThrowsWhenMissing() throws Exception {
        JsonNode body = json("{\"other\":\"value\"}");

        expectThrows(
            IllegalArgumentException.class,
            () -> InputValidation.getRequiredText(body, "source_index", InputValidation.MAX_INDEX_NAME_LENGTH)
        );
    }

    @Test
    public void testGetRequiredTextThrowsWhenNonTextual() throws Exception {
        JsonNode body = json("{\"source_index\":123}");

        expectThrows(
            IllegalArgumentException.class,
            () -> InputValidation.getRequiredText(body, "source_index", InputValidation.MAX_INDEX_NAME_LENGTH)
        );
    }

    /* ---------------------- getOptionalText ---------------------- */

    @Test
    public void testGetOptionalTextReturnsNullWhenMissing() throws Exception {
        JsonNode body = json("{\"other\":\"value\"}");

        String result = InputValidation.getOptionalText(body, "default_owner", InputValidation.MAX_PRINCIPAL_LENGTH);

        assertNull(result);
    }

    @Test
    public void testGetOptionalTextReturnsValueWhenPresent() throws Exception {
        JsonNode body = json("{\"default_owner\":\"owner_1\"}");

        String result = InputValidation.getOptionalText(body, "default_owner", InputValidation.MAX_PRINCIPAL_LENGTH);

        assertEquals("owner_1", result);
    }

    @Test
    public void testGetOptionalTextThrowsWhenNonTextual() throws Exception {
        JsonNode body = json("{\"default_owner\":123}");

        expectThrows(
            IllegalArgumentException.class,
            () -> InputValidation.getOptionalText(body, "default_owner", InputValidation.MAX_PRINCIPAL_LENGTH)
        );
    }

    /* ---------------------- validateJsonPath ---------------------- */

    @Test
    public void testValidateJsonPathAcceptsValidPath() {
        InputValidation.validateJsonPath("username_path", "user.details.name");
    }

    @Test
    public void testValidateJsonPathRejectsEmpty() {
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateJsonPath("username_path", ""));
    }

    @Test
    public void testValidateJsonPathRejectsWhitespace() {
        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateJsonPath("username_path", " user . name "));
    }

    /* ---------------------- validateSourceIndex ---------------------- */

    @Test
    public void testValidateSourceIndexAcceptsWhenInAllowedSet() {
        Set<String> allowed = new HashSet<>();
        allowed.add("index-1");
        allowed.add("index-2");

        InputValidation.validateSourceIndex("index-1", allowed);
    }

    @Test
    public void testValidateSourceIndexRejectsWhenNotInAllowedSet() {
        Set<String> allowed = new HashSet<>();
        allowed.add("index-1");

        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateSourceIndex("index-2", allowed));
    }

    @Test
    public void testValidateSourceIndexRejectsWhenNoIndicesConfiguredNull() {
        expectThrows(IllegalStateException.class, () -> InputValidation.validateSourceIndex("index-1", null));
    }

    @Test
    public void testValidateSourceIndexRejectsWhenNoIndicesConfiguredEmpty() {
        expectThrows(IllegalStateException.class, () -> InputValidation.validateSourceIndex("index-1", Collections.emptySet()));
    }

    /* ---------------------- validateDefaultOwner ---------------------- */

    @Test
    public void testValidateDefaultOwnerAllowsNull() {
        // optional field
        InputValidation.validateDefaultOwner(null);
    }

    @Test
    public void testValidateDefaultOwnerAcceptsValidPrincipal() {
        InputValidation.validateDefaultOwner("owner_123-role:1");
    }

    @Test
    public void testValidateDefaultOwnerRejectsInvalidCharacters() {
        expectThrows(
            IllegalArgumentException.class,
            () -> InputValidation.validateDefaultOwner("owner name") // space
        );
    }

    /* ---------------------- validateDefaultAccessLevelNode ---------------------- */

    @Test
    public void testValidateDefaultAccessLevelNodeAllowsNull() {
        // field absent / null is allowed (optional)
        InputValidation.validateDefaultAccessLevelNode(null);
    }

    @Test
    public void testValidateDefaultAccessLevelNodeRejectsNonObject() throws Exception {
        JsonNode node = json("\"string-not-object\"");

        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateDefaultAccessLevelNode(node));
    }

    @Test
    public void testValidateDefaultAccessLevelNodeRejectsEmptyObject() throws Exception {
        JsonNode node = json("{}");

        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateDefaultAccessLevelNode(node));
    }

    @Test
    public void testValidateDefaultAccessLevelNodeRejectsEmptyValue() throws Exception {
        JsonNode node = json("{\"anomaly-detector\":\"\"}");

        expectThrows(IllegalArgumentException.class, () -> InputValidation.validateDefaultAccessLevelNode(node));
    }

    @Test
    public void testValidateDefaultAccessLevelNodeAcceptsNonEmptyValues() throws Exception {
        JsonNode node = json("{ \"anomaly-detector\": \"rd_read_only\", \"forecaster\": \"rd_write\" }");

        // should not throw
        InputValidation.validateDefaultAccessLevelNode(node);
    }
}
