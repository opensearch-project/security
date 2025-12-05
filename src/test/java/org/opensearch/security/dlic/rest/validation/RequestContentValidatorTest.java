/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.dlic.rest.validation;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.http.HttpChannel;
import org.opensearch.http.HttpRequest;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class RequestContentValidatorTest {

    @Mock
    private HttpRequest httpRequest;

    @Mock
    private NamedXContentRegistry xContentRegistry;

    @Mock
    private HttpChannel httpChannel;

    private RestRequest request;

    @Before
    public void setUpRequest() {
        when(httpRequest.uri()).thenReturn("");
        when(httpRequest.content()).thenReturn(new BytesArray(new byte[1]));
        when(httpRequest.getHeaders()).thenReturn(
                Collections.singletonMap("Content-Type", Collections.singletonList("application/json"))
        );
        request = RestRequest.request(xContentRegistry, httpRequest, httpChannel);
    }

    @Test
    public void testParseRequestContent() throws Exception {
        final RequestContentValidator validator = RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
            @Override
            public Object[] params() {
                return new Object[0];
            }

            @Override
            public Settings settings() {
                return Settings.EMPTY;
            }

            @Override
            public Map<String, RequestContentValidator.DataType> allowedKeys() {
                return Collections.emptyMap();
            }
        });
        when(httpRequest.content()).thenReturn(new BytesArray("{`a`: `b`}"));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);
        assertFalse(validationResult.isValid());
        assertErrorMessage(validationResult.errorMessage(), RequestContentValidator.ValidationError.BODY_NOT_PARSEABLE);
    }

    @Test
    public void testValidateContentSize() throws Exception {
        final RequestContentValidator validator = RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
            @Override
            public Object[] params() {
                return new Object[0];
            }

            @Override
            public Settings settings() {
                return Settings.EMPTY;
            }

            @Override
            public Map<String, RequestContentValidator.DataType> allowedKeys() {
                return Collections.emptyMap();
            }
        });
        when(httpRequest.content()).thenReturn(new BytesArray(""));
        ValidationResult<JsonNode> validationResult = validator.validate(request);
        assertFalse(validationResult.isValid());
        assertErrorMessage(validationResult.errorMessage(), RequestContentValidator.ValidationError.PAYLOAD_MANDATORY);

        when(httpRequest.content()).thenReturn(new BytesArray("{}"));
        validationResult = validator.validate(request);
        assertFalse(validationResult.isValid());
        assertErrorMessage(validationResult.errorMessage(), RequestContentValidator.ValidationError.PAYLOAD_MANDATORY);
    }

    @Test
    public void testValidateDataTypes() throws Exception {
        final RequestContentValidator validator = RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
            @Override
            public Object[] params() {
                return new Object[0];
            }

            @Override
            public Settings settings() {
                return Settings.EMPTY;
            }

            @Override
            public Map<String, RequestContentValidator.DataType> allowedKeys() {
                return ImmutableMap.of(
                    "a",
                    RequestContentValidator.DataType.STRING,
                    "b",
                    RequestContentValidator.DataType.OBJECT,
                    "c",
                    RequestContentValidator.DataType.ARRAY,
                    "d",
                    RequestContentValidator.DataType.INTEGER
                );
            }
        });

        final JsonNode payload = DefaultObjectMapper.objectMapper.createObjectNode()
            .put("a", 1)
            .put("b", "[]")
            .put("c", "{}")
            .put("d", "1");
        when(httpRequest.content()).thenReturn(new BytesArray(payload.toString()));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);

        final JsonNode errorMessage = xContentToJsonNode(validationResult.errorMessage());
        assertFalse(validationResult.isValid());
        assertErrorMessage(errorMessage, RequestContentValidator.ValidationError.WRONG_DATATYPE);

        assertThat(errorMessage.get("a").asText(), is("String expected"));
        assertThat(errorMessage.get("b").asText(), is("Object expected"));
        assertThat(errorMessage.get("c").asText(), is("Array expected"));
        assertThat(errorMessage.get("d").asText(), is("Integer expected"));
    }

    @Test
    public void testValidateJsonKeys() throws Exception {
        final RequestContentValidator validator = RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
            @Override
            public Object[] params() {
                return new Object[0];
            }

            @Override
            public Settings settings() {
                return Settings.EMPTY;
            }

            @Override
            public Set<String> mandatoryKeys() {
                return Set.of("a");
            }

            @Override
            public Map<String, RequestContentValidator.DataType> allowedKeys() {
                return Map.of("a", RequestContentValidator.DataType.STRING, "b", RequestContentValidator.DataType.STRING);
            }
        });

        final JsonNode payload = DefaultObjectMapper.objectMapper.createObjectNode().put("c", "aaa").put("d", "aaa");
        when(httpRequest.content()).thenReturn(new BytesArray(payload.toString()));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);
        final JsonNode errorMessage = xContentToJsonNode(validationResult.errorMessage());
        assertErrorMessage(errorMessage, RequestContentValidator.ValidationError.INVALID_CONFIGURATION);

        assertThat(errorMessage.get("invalid_keys").toString(), is("{\"keys\":\"c,d\"}"));
        assertThat(errorMessage.get("missing_mandatory_keys").toString(), is("{\"keys\":\"a\"}"));
    }

    @Test
    public void testNullValuesInArray() throws Exception {
        final RequestContentValidator validator = RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
            @Override
            public Object[] params() {
                return new Object[0];
            }

            @Override
            public Settings settings() {
                return Settings.EMPTY;
            }

            @Override
            public Set<String> mandatoryKeys() {
                return ImmutableSet.of("a");
            }

            @Override
            public Map<String, RequestContentValidator.DataType> allowedKeys() {
                return ImmutableMap.of("a", RequestContentValidator.DataType.ARRAY);
            }
        });
        final ObjectNode payload = DefaultObjectMapper.objectMapper.createObjectNode().putObject("a");
        payload.putArray("a").add(NullNode.getInstance()).add("b").add("c");
        when(request.content()).thenReturn(new BytesArray(payload.toString()));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);
        assertErrorMessage(validationResult.errorMessage(), RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT);
    }

    @Test
    public void testValidatePassword() throws Exception {
        final RequestContentValidator validator = RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
            @Override
            public Object[] params() {
                return new Object[0];
            }

            @Override
            public Settings settings() {
                return Settings.EMPTY;
            }

            @Override
            public Set<String> mandatoryKeys() {
                return ImmutableSet.of("password");
            }

            @Override
            public Map<String, RequestContentValidator.DataType> allowedKeys() {
                return ImmutableMap.of("password", RequestContentValidator.DataType.STRING);
            }
        });
        ObjectNode payload = DefaultObjectMapper.objectMapper.createObjectNode().put("password", "a");
        when(httpRequest.content()).thenReturn(new BytesArray(payload.toString()));
        ValidationResult<JsonNode> validationResult = validator.validate(request);
        assertErrorMessage(validationResult.errorMessage(), RequestContentValidator.ValidationError.NO_USERNAME);

        when(httpRequest.uri()).thenReturn("/aaaa?name=a");
        when(request.content()).thenReturn(new BytesArray(payload.toString()));
        validationResult = validator.validate(RestRequest.request(xContentRegistry, httpRequest, httpChannel));
        assertErrorMessage(validationResult.errorMessage(), RequestContentValidator.ValidationError.WEAK_PASSWORD);
    }

    @Test
    public void testValidationSuccess() throws Exception {
        final RequestContentValidator validator = RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
            @Override
            public Object[] params() {
                return new Object[0];
            }

            @Override
            public Settings settings() {
                return Settings.EMPTY;
            }

            @Override
            public Map<String, RequestContentValidator.DataType> allowedKeys() {
                return ImmutableMap.of(
                    "a",
                    RequestContentValidator.DataType.ARRAY,
                    "b",
                    RequestContentValidator.DataType.BOOLEAN,
                    "c",
                    RequestContentValidator.DataType.OBJECT,
                    "d",
                    RequestContentValidator.DataType.STRING,
                    "e",
                    RequestContentValidator.DataType.BOOLEAN,
                    "f",
                    RequestContentValidator.DataType.INTEGER
                );
            }
        });

        ObjectNode payload = DefaultObjectMapper.objectMapper.createObjectNode().putObject("a");
        payload.putArray("a").add("arrray");
        payload.put("b", true).put("d", "some_string").put("e", false).put("f", 1);
        payload.putObject("c");

        when(httpRequest.content()).thenReturn(new BytesArray(payload.toString()));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);
        assertTrue(validationResult.isValid());
        assertNull(validationResult.errorMessage());
    }

    private JsonNode xContentToJsonNode(final ToXContent toXContent) throws IOException {
        try (final var xContentBuilder = XContentFactory.jsonBuilder()) {
            toXContent.toXContent(xContentBuilder, ToXContent.EMPTY_PARAMS);
            return DefaultObjectMapper.readTree(xContentBuilder.toString());
        }
    }

    private void assertErrorMessage(final ToXContent toXContent, final RequestContentValidator.ValidationError expectedValidationError)
        throws IOException {
        final var jsonNode = xContentToJsonNode(toXContent);
        assertErrorMessage(jsonNode, expectedValidationError);
    }

    private void assertErrorMessage(final JsonNode jsonNode, final RequestContentValidator.ValidationError expectedValidationError) {
        assertThat(jsonNode.get("status").asText(), is("error"));
        assertThat(jsonNode.get("reason").asText(), is(expectedValidationError.message()));
    }

    /* ========================================================================
     * Tests for Static Utility Methods (moved from InputValidationTests)
     * ======================================================================== */

    private static String repeat(char c, int count) {
        char[] arr = new char[count];
        Arrays.fill(arr, c);
        return new String(arr);
    }

    private static <T extends Throwable> void expectThrows(Class<T> expected, Runnable runnable) {
        try {
            runnable.run();
            org.junit.Assert.fail("Expected exception of type " + expected.getName());
        } catch (Throwable t) {
            assertTrue(
                "Unexpected exception type. Expected " + expected.getName() + " but got " + t.getClass().getName(),
                expected.isInstance(t)
            );
        }
    }

    /* ---------------------- requireNonEmpty ---------------------- */

    @Test
    public void testRequireNonEmptyAcceptsNonEmpty() {
        RequestContentValidator.requireNonEmpty("field", "value");
    }

    @Test
    public void testRequireNonEmptyRejectsNull() {
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.requireNonEmpty("field", null));
    }

    @Test
    public void testRequireNonEmptyRejectsEmpty() {
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.requireNonEmpty("field", ""));
    }

    /* ---------------------- validateMaxLength ---------------------- */

    @Test
    public void testValidateMaxLengthAtBoundary() {
        String value = repeat('a', 5);
        RequestContentValidator.validateMaxLength("field", value, 5);
    }

    @Test
    public void testValidateMaxLengthRejectsOverLimit() {
        String value = repeat('a', 6);
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateMaxLength("field", value, 5));
    }

    /* ---------------------- validateSafeValue ---------------------- */

    @Test
    public void testValidateSafeValueAcceptsAllowedCharacters() {
        String value = "Abc123_-:xyz";
        RequestContentValidator.validateSafeValue("field", value, 50);
    }

    @Test
    public void testValidateSafeValueRejectsInvalidCharacters() {
        String value = "bad value$"; // space + $
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateSafeValue("field", value, 50));
    }

    @Test
    public void testValidateSafeValueRejectsTooLong() {
        String value = repeat('a', 11);
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateSafeValue("field", value, 10));
    }

    /* ---------------------- validateArrayEntryCount ---------------------- */

    @Test
    public void testValidateArrayEntryCountAtMaxBoundary() {
        RequestContentValidator.validateArrayEntryCount("field", RequestContentValidator.MAX_ARRAY_SIZE);
    }

    @Test
    public void testValidateArrayEntryCountRejectsAboveMax() {
        int overMax = RequestContentValidator.MAX_ARRAY_SIZE + 1;
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateArrayEntryCount("field", overMax));
    }

    /* ---------------------- validateResourceId ---------------------- */

    @Test
    public void testValidateResourceIdAcceptsValidId() {
        String id = "resource_123-ABC:xyz";
        RequestContentValidator.validateResourceId(id);
    }

    @Test
    public void testValidateResourceIdRejectsInvalidCharacters() {
        String id = "invalid id!"; // space + !
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateResourceId(id));
    }

    @Test
    public void testValidateResourceIdRejectsTooLong() {
        String id = repeat('a', RequestContentValidator.MAX_RESOURCE_ID_LENGTH + 1);
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateResourceId(id));
    }

    /* ---------------------- validateResourceType ---------------------- */

    @Test
    public void testValidateResourceTypeAcceptsValidTypeInAllowedList() {
        List<String> allowedTypes = Arrays.asList("anomaly-detector", "forecaster", "ml-model");
        RequestContentValidator.validateResourceType("anomaly-detector", allowedTypes);
    }

    @Test
    public void testValidateResourceTypeRejectsInvalidCharacters() {
        List<String> allowedTypes = List.of("anomaly-detector");
        String resourceType = "anomaly detector"; // contains space
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateResourceType(resourceType, allowedTypes));
    }

    @Test
    public void testValidateResourceTypeRejectsWhenNoAllowedTypesConfiguredNull() {
        expectThrows(IllegalStateException.class, () -> RequestContentValidator.validateResourceType("anomaly-detector", null));
    }

    @Test
    public void testValidateResourceTypeRejectsWhenNoAllowedTypesConfiguredEmpty() {
        expectThrows(
            IllegalStateException.class,
            () -> RequestContentValidator.validateResourceType("anomaly-detector", Collections.emptyList())
        );
    }

    @Test
    public void testValidateResourceTypeRejectsWhenTypeNotInAllowedList() {
        List<String> allowedTypes = Arrays.asList("anomaly-detector", "forecaster");
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateResourceType("ml-model", allowedTypes));
    }

    /* ---------------------- validatePrincipalValue ---------------------- */

    @Test
    public void testValidatePrincipalValueAcceptsValidPrincipal() {
        RequestContentValidator.validatePrincipalValue("users", "user_123-role:1");
    }

    @Test
    public void testValidatePrincipalValueRejectsInvalidCharacters() {
        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.validatePrincipalValue("users", "user name") // space
        );
    }

    @Test
    public void testValidatePrincipalValueRejectsTooLong() {
        String principal = repeat('u', RequestContentValidator.MAX_PRINCIPAL_LENGTH + 1);
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validatePrincipalValue("users", principal));
    }

    /* ---------------------- validateAccessLevel ---------------------- */

    @Test
    public void testValidateAccessLevelAcceptsValidValueInSet() {
        Set<String> allowed = new HashSet<>(Arrays.asList("rd_read_only", "rd_write", "forecast:read", "forecast:write"));

        RequestContentValidator.validateAccessLevel("rd_read_only", allowed);
        RequestContentValidator.validateAccessLevel("forecast:write", allowed);
    }

    @Test
    public void testValidateAccessLevelRejectsNullAccessLevel() {
        Set<String> allowed = new HashSet<>(List.of("rd_read_only"));
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateAccessLevel(null, allowed));
    }

    @Test
    public void testValidateAccessLevelRejectsEmptyAccessLevel() {
        Set<String> allowed = new HashSet<>(List.of("rd_read_only"));
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateAccessLevel("", allowed));
    }

    @Test
    public void testValidateAccessLevelRejectsTooLongAccessLevel() {
        Set<String> allowed = new HashSet<>(List.of("rd_read_only"));
        String longAccess = repeat('a', RequestContentValidator.MAX_ACCESS_LEVEL_LENGTH + 1);
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateAccessLevel(longAccess, allowed));
    }

    @Test
    public void testValidateAccessLevelRejectsInvalidCharacters() {
        Set<String> allowed = new HashSet<>(List.of("rd_read_only"));
        String invalid = "rd read"; // space
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateAccessLevel(invalid, allowed));
    }

    @Test
    public void testValidateAccessLevelRejectsWhenNoAccessLevelsConfiguredNull() {
        expectThrows(IllegalStateException.class, () -> RequestContentValidator.validateAccessLevel("rd_read_only", null));
    }

    @Test
    public void testValidateAccessLevelRejectsWhenNoAccessLevelsConfiguredEmpty() {
        expectThrows(
            IllegalStateException.class,
            () -> RequestContentValidator.validateAccessLevel("rd_read_only", Collections.emptySet())
        );
    }

    @Test
    public void testValidateAccessLevelRejectsWhenNotInAllowedSet() {
        Set<String> allowed = new HashSet<>(Arrays.asList("rd_read_only", "rd_write"));
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateAccessLevel("forecast:read", allowed));
    }

    /* ---------------------- getRequiredText ---------------------- */

    @Test
    public void testGetRequiredTextReturnsValueWhenPresent() throws Exception {
        JsonNode body = DefaultObjectMapper.readTree("{\"source_index\":\"index-1\"}");

        String result = RequestContentValidator.getRequiredText(body, "source_index", RequestContentValidator.MAX_INDEX_NAME_LENGTH);

        assertThat(result, is("index-1"));
    }

    @Test
    public void testGetRequiredTextThrowsWhenMissing() throws Exception {
        JsonNode body = DefaultObjectMapper.readTree("{\"other\":\"value\"}");

        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.getRequiredText(body, "source_index", RequestContentValidator.MAX_INDEX_NAME_LENGTH)
        );
    }

    @Test
    public void testGetRequiredTextThrowsWhenNonTextual() throws Exception {
        JsonNode body = DefaultObjectMapper.readTree("{\"source_index\":123}");

        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.getRequiredText(body, "source_index", RequestContentValidator.MAX_INDEX_NAME_LENGTH)
        );
    }

    /* ---------------------- getOptionalText ---------------------- */

    @Test
    public void testGetOptionalTextReturnsNullWhenMissing() throws Exception {
        JsonNode body = DefaultObjectMapper.readTree("{\"other\":\"value\"}");

        String result = RequestContentValidator.getOptionalText(body, "default_owner", RequestContentValidator.MAX_PRINCIPAL_LENGTH);

        assertNull(result);
    }

    @Test
    public void testGetOptionalTextReturnsValueWhenPresent() throws Exception {
        JsonNode body = DefaultObjectMapper.readTree("{\"default_owner\":\"owner_1\"}");

        String result = RequestContentValidator.getOptionalText(body, "default_owner", RequestContentValidator.MAX_PRINCIPAL_LENGTH);

        assertThat(result, is("owner_1"));
    }

    @Test
    public void testGetOptionalTextThrowsWhenNonTextual() throws Exception {
        JsonNode body = DefaultObjectMapper.readTree("{\"default_owner\":123}");

        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.getOptionalText(body, "default_owner", RequestContentValidator.MAX_PRINCIPAL_LENGTH)
        );
    }

    /* ---------------------- validateJsonPath ---------------------- */

    @Test
    public void testValidateJsonPathAcceptsValidPath() {
        RequestContentValidator.validateJsonPath("username_path", "user.details.name");
    }

    @Test
    public void testValidateJsonPathRejectsEmpty() {
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateJsonPath("username_path", ""));
    }

    @Test
    public void testValidateJsonPathRejectsWhitespace() {
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateJsonPath("username_path", " user . name "));
    }

    /* ---------------------- validateSourceIndex ---------------------- */

    @Test
    public void testValidateSourceIndexAcceptsWhenInAllowedSet() {
        Set<String> allowed = new HashSet<>();
        allowed.add("index-1");
        allowed.add("index-2");

        RequestContentValidator.validateSourceIndex("index-1", allowed);
    }

    @Test
    public void testValidateSourceIndexRejectsWhenNotInAllowedSet() {
        Set<String> allowed = new HashSet<>();
        allowed.add("index-1");

        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateSourceIndex("index-2", allowed));
    }

    @Test
    public void testValidateSourceIndexRejectsWhenNoIndicesConfiguredNull() {
        expectThrows(IllegalStateException.class, () -> RequestContentValidator.validateSourceIndex("index-1", null));
    }

    @Test
    public void testValidateSourceIndexRejectsWhenNoIndicesConfiguredEmpty() {
        expectThrows(IllegalStateException.class, () -> RequestContentValidator.validateSourceIndex("index-1", Collections.emptySet()));
    }

    /* ---------------------- validateDefaultOwner ---------------------- */

    @Test
    public void testValidateDefaultOwnerAllowsNull() {
        // optional field
        RequestContentValidator.validateDefaultOwner(null);
    }

    @Test
    public void testValidateDefaultOwnerAcceptsValidPrincipal() {
        RequestContentValidator.validateDefaultOwner("owner_123-role:1");
    }

    @Test
    public void testValidateDefaultOwnerRejectsInvalidCharacters() {
        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.validateDefaultOwner("owner name") // space
        );
    }

    /* ---------------------- validateDefaultAccessLevelNode ---------------------- */

    @Test
    public void testValidateDefaultAccessLevelNodeAllowsNull() {
        // field absent / null is allowed (optional)
        RequestContentValidator.validateDefaultAccessLevelNode(null);
    }

    @Test
    public void testValidateDefaultAccessLevelNodeRejectsNonObject() throws Exception {
        JsonNode node = DefaultObjectMapper.readTree("\"string-not-object\"");

        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateDefaultAccessLevelNode(node));
    }

    @Test
    public void testValidateDefaultAccessLevelNodeRejectsEmptyObject() throws Exception {
        JsonNode node = DefaultObjectMapper.readTree("{}");

        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateDefaultAccessLevelNode(node));
    }

    @Test
    public void testValidateDefaultAccessLevelNodeRejectsEmptyValue() throws Exception {
        JsonNode node = DefaultObjectMapper.readTree("{\"anomaly-detector\":\"\"}");

        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.validateDefaultAccessLevelNode(node));
    }

    @Test
    public void testValidateDefaultAccessLevelNodeAcceptsNonEmptyValues() throws Exception {
        JsonNode node = DefaultObjectMapper.readTree("{ \"anomaly-detector\": \"rd_read_only\", \"forecaster\": \"rd_write\" }");

        // should not throw
        RequestContentValidator.validateDefaultAccessLevelNode(node);
    }

}
