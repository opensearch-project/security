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
    public void testBlankValuesInArray() throws Exception {
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
                return Map.of("a", RequestContentValidator.DataType.ARRAY);
            }
        });
        final ObjectNode payload = DefaultObjectMapper.objectMapper.createObjectNode();
        payload.putArray("a").add("  ").add("b");
        when(request.content()).thenReturn(new BytesArray(payload.toString()));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);
        assertErrorMessage(validationResult.errorMessage(), RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT);
    }

    @Test
    public void testMandatoryOrKeys() throws Exception {
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
            public Set<String> mandatoryOrKeys() {
                return Set.of("a", "b");
            }

            @Override
            public Map<String, RequestContentValidator.DataType> allowedKeys() {
                return Map.of("a", RequestContentValidator.DataType.STRING, "b", RequestContentValidator.DataType.STRING);
            }
        });
        final JsonNode payload = DefaultObjectMapper.objectMapper.createObjectNode().put("a", "value");
        when(httpRequest.content()).thenReturn(new BytesArray(payload.toString()));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);
        assertTrue(validationResult.isValid());
    }

    @Test
    public void testMandatoryOrKeysMissing() throws Exception {
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
            public Set<String> mandatoryOrKeys() {
                return Set.of("a", "b");
            }

            @Override
            public Map<String, RequestContentValidator.DataType> allowedKeys() {
                return Map.of(
                    "a",
                    RequestContentValidator.DataType.STRING,
                    "b",
                    RequestContentValidator.DataType.STRING,
                    "c",
                    RequestContentValidator.DataType.STRING
                );
            }
        });
        final JsonNode payload = DefaultObjectMapper.objectMapper.createObjectNode().put("c", "value");
        when(httpRequest.content()).thenReturn(new BytesArray(payload.toString()));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);
        assertFalse(validationResult.isValid());
        final JsonNode errorMessage = xContentToJsonNode(validationResult.errorMessage());
        assertThat(errorMessage.get("specify_one_of").get("keys").asText(), is("a,b"));
    }

    @Test
    public void testFieldConfigurationWithMaxLength() throws Exception {
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
                return Map.of("a", RequestContentValidator.DataType.STRING);
            }

            @Override
            public Map<String, RequestContentValidator.FieldConfiguration> allowedKeysWithConfig() {
                return Map.of("a", RequestContentValidator.FieldConfiguration.of(RequestContentValidator.DataType.STRING, 5));
            }
        });
        final JsonNode payload = DefaultObjectMapper.objectMapper.createObjectNode().put("a", "toolong");
        when(httpRequest.content()).thenReturn(new BytesArray(payload.toString()));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);
        assertFalse(validationResult.isValid());
        final JsonNode errorMessage = xContentToJsonNode(validationResult.errorMessage());
        assertThat(errorMessage.get("a").asText(), is("a length [7] exceeds max [5]"));
    }

    @Test
    public void testFieldConfigurationWithCustomValidator() throws Exception {
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
                return Map.of("a", RequestContentValidator.DataType.STRING);
            }

            @Override
            public Map<String, RequestContentValidator.FieldConfiguration> allowedKeysWithConfig() {
                return Map.of(
                    "a",
                    RequestContentValidator.FieldConfiguration.of(RequestContentValidator.DataType.STRING, (fieldName, value) -> {
                        if (value instanceof String && ((String) value).contains("bad")) {
                            throw new IllegalArgumentException("Value contains 'bad'");
                        }
                    })
                );
            }
        });
        final JsonNode payload = DefaultObjectMapper.objectMapper.createObjectNode().put("a", "bad_value");
        when(httpRequest.content()).thenReturn(new BytesArray(payload.toString()));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);
        assertFalse(validationResult.isValid());
        final JsonNode errorMessage = xContentToJsonNode(validationResult.errorMessage());
        assertThat(errorMessage.get("a").asText(), is("Value contains 'bad'"));
    }

    @Test
    public void testFieldConfigurationArrayValidator() throws Exception {
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
                return Map.of("a", RequestContentValidator.DataType.ARRAY);
            }

            @Override
            public Map<String, RequestContentValidator.FieldConfiguration> allowedKeysWithConfig() {
                return Map.of(
                    "a",
                    RequestContentValidator.FieldConfiguration.of(RequestContentValidator.DataType.ARRAY, (fieldName, value) -> {
                        if (value instanceof JsonNode && ((JsonNode) value).size() > 2) {
                            throw new IllegalArgumentException("Array too large");
                        }
                    })
                );
            }
        });
        final ObjectNode payload = DefaultObjectMapper.objectMapper.createObjectNode();
        payload.putArray("a").add("1").add("2").add("3");
        when(httpRequest.content()).thenReturn(new BytesArray(payload.toString()));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);
        assertFalse(validationResult.isValid());
        final JsonNode errorMessage = xContentToJsonNode(validationResult.errorMessage());
        assertThat(errorMessage.get("a").asText(), is("Array too large"));
    }

    @Test
    public void testFieldConfigurationObjectValidator() throws Exception {
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
                return Map.of("a", RequestContentValidator.DataType.OBJECT);
            }

            @Override
            public Map<String, RequestContentValidator.FieldConfiguration> allowedKeysWithConfig() {
                return Map.of(
                    "a",
                    RequestContentValidator.FieldConfiguration.of(RequestContentValidator.DataType.OBJECT, (fieldName, value) -> {
                        if (value instanceof JsonNode && !((JsonNode) value).has("required")) {
                            throw new IllegalArgumentException("Missing required field");
                        }
                    })
                );
            }
        });
        final ObjectNode payload = DefaultObjectMapper.objectMapper.createObjectNode();
        payload.putObject("a").put("other", "value");
        when(httpRequest.content()).thenReturn(new BytesArray(payload.toString()));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);
        assertFalse(validationResult.isValid());
        final JsonNode errorMessage = xContentToJsonNode(validationResult.errorMessage());
        assertThat(errorMessage.get("a").asText(), is("Missing required field"));
    }

    @Test
    public void testValidateWithPatchNoDiff() throws Exception {
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
                return Map.of("a", RequestContentValidator.DataType.STRING);
            }
        });
        final JsonNode original = DefaultObjectMapper.objectMapper.createObjectNode().put("a", "value");
        final JsonNode patched = DefaultObjectMapper.objectMapper.createObjectNode().put("a", "value");
        final ValidationResult<JsonNode> validationResult = validator.validate(request, patched, original);
        assertFalse(validationResult.isValid());
    }

    @Test
    public void testValidateWithPatchWithDiff() throws Exception {
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
                return Map.of("a", RequestContentValidator.DataType.STRING);
            }
        });
        final JsonNode original = DefaultObjectMapper.objectMapper.createObjectNode().put("a", "value1");
        final JsonNode patched = DefaultObjectMapper.objectMapper.createObjectNode().put("a", "value2");
        final ValidationResult<JsonNode> validationResult = validator.validate(request, patched, original);
        assertTrue(validationResult.isValid());
    }

    @Test
    public void testNoopValidator() throws Exception {
        final ValidationResult<JsonNode> validationResult = RequestContentValidator.NOOP_VALIDATOR.validate(request);
        assertTrue(validationResult.isValid());
    }

    @Test
    public void testNoopValidatorWithJsonNode() throws Exception {
        final JsonNode jsonNode = DefaultObjectMapper.objectMapper.createObjectNode();
        final ValidationResult<JsonNode> validationResult = RequestContentValidator.NOOP_VALIDATOR.validate(request, jsonNode);
        assertTrue(validationResult.isValid());
    }

    @Test
    public void testValidatePasswordEmptyPassword() throws Exception {
        final RequestContentValidator validator = RequestContentValidator.of(new RequestContentValidator.ValidationContext() {
            @Override
            public Object[] params() {
                return new Object[] { "testuser" };
            }

            @Override
            public Settings settings() {
                return Settings.EMPTY;
            }

            @Override
            public Map<String, RequestContentValidator.DataType> allowedKeys() {
                return Map.of("password", RequestContentValidator.DataType.STRING);
            }
        });
        final JsonNode payload = DefaultObjectMapper.objectMapper.createObjectNode().put("password", "");
        when(httpRequest.content()).thenReturn(new BytesArray(payload.toString()));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);
        assertErrorMessage(validationResult.errorMessage(), RequestContentValidator.ValidationError.INVALID_PASSWORD_TOO_SHORT);
    }

    @Test
    public void testNestedNullInArray() throws Exception {
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
                return Map.of("a", RequestContentValidator.DataType.OBJECT);
            }
        });
        final ObjectNode payload = DefaultObjectMapper.objectMapper.createObjectNode();
        final ObjectNode nested = payload.putObject("a");
        nested.putArray("inner").add(NullNode.getInstance());
        when(request.content()).thenReturn(new BytesArray(payload.toString()));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);
        assertErrorMessage(validationResult.errorMessage(), RequestContentValidator.ValidationError.NULL_ARRAY_ELEMENT);
    }

    @Test
    public void testValidateSafeValueWithWildcard() {
        RequestContentValidator.validateSafeValue("field", "*", 10, true);
    }

    @Test
    public void testValidateSafeValueAcceptsWildcardInPattern() {
        // "*" matches the pattern even when allowWildcard is false, because the pattern allows it
        RequestContentValidator.validateSafeValue("field", "*", 10, false);
    }

    @Test
    public void testPrincipalValidator() {
        RequestContentValidator.principalValidator(false).validate("user", "valid_user-123:role");
    }

    @Test
    public void testPrincipalValidatorWithWildcard() {
        RequestContentValidator.principalValidator(true).validate("user", "*");
    }

    @Test
    public void testPathValidator() {
        RequestContentValidator.PATH_VALIDATOR.validate("path", "valid.path.name");
    }

    @Test
    public void testPathValidatorRejectsWhitespace() {
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.PATH_VALIDATOR.validate("path", "invalid path"));
    }

    @Test
    public void testArraySizeValidatorWithJsonNode() {
        final ObjectNode node = DefaultObjectMapper.objectMapper.createObjectNode();
        node.putArray("arr").add("1").add("2");
        RequestContentValidator.ARRAY_SIZE_VALIDATOR.validate("arr", node.get("arr"));
    }

    @Test
    public void testArraySizeValidatorRejectsLargeArray() {
        final ObjectNode node = DefaultObjectMapper.objectMapper.createObjectNode();
        final var arr = node.putArray("arr");
        for (int i = 0; i <= RequestContentValidator.MAX_ARRAY_SIZE; i++) {
            arr.add(String.valueOf(i));
        }
        expectThrows(IllegalArgumentException.class, () -> RequestContentValidator.ARRAY_SIZE_VALIDATOR.validate("arr", node.get("arr")));
    }

    @Test
    public void testArraySizeValidatorWithInteger() {
        RequestContentValidator.ARRAY_SIZE_VALIDATOR.validate("count", 100);
    }

    @Test
    public void testArraySizeValidatorRejectsLargeCount() {
        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.ARRAY_SIZE_VALIDATOR.validate("count", RequestContentValidator.MAX_ARRAY_SIZE + 1)
        );
    }

    @Test
    public void testAllowedValuesValidator() {
        final Set<String> allowed = Set.of("read", "write");
        final RequestContentValidator.FieldValidator validator = RequestContentValidator.allowedValuesValidator(allowed);
        validator.validate("action", "read");
    }

    @Test
    public void testAllowedValuesValidatorRejectsInvalid() {
        final Set<String> allowed = Set.of("read", "write");
        final RequestContentValidator.FieldValidator validator = RequestContentValidator.allowedValuesValidator(allowed);
        expectThrows(IllegalArgumentException.class, () -> validator.validate("action", "delete"));
    }

    @Test
    public void testAllowedValuesValidatorWithCustomMessage() {
        final Set<String> allowed = Set.of("read", "write");
        final RequestContentValidator.FieldValidator validator = RequestContentValidator.allowedValuesValidator(allowed, "Custom error");
        expectThrows(IllegalArgumentException.class, () -> validator.validate("action", "delete"));
    }

    @Test
    public void testValidateNonEmptyValuesInAnObjectAcceptsNullNode() throws Exception {
        JsonNode body = DefaultObjectMapper.readTree("{\"field\":null}");
        // Should not throw - null is allowed
        RequestContentValidator.validateNonEmptyValuesInAnObject("field", body.get("field"));
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

    /* ---------------------- validateSafeValue (for IDs) ---------------------- */

    @Test
    public void testValidateSafeValueAcceptsValidId() {
        String id = "resource_123-ABC:xyz";
        RequestContentValidator.validateSafeValue("resource_id", id, RequestContentValidator.MAX_STRING_LENGTH);
    }

    @Test
    public void testValidateSafeValueRejectsInvalidCharactersInId() {
        String id = "invalid id!"; // space + !
        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.validateSafeValue("resource_id", id, RequestContentValidator.MAX_STRING_LENGTH)
        );
    }

    @Test
    public void testValidateSafeValueRejectsTooLongId() {
        String id = repeat('a', RequestContentValidator.MAX_STRING_LENGTH + 1);
        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.validateSafeValue("resource_id", id, RequestContentValidator.MAX_STRING_LENGTH)
        );
    }

    /* ---------------------- validateType (generic) ---------------------- */

    @Test
    public void testValidateValueInSetAcceptsValidTypeInAllowedList() {
        List<String> allowedTypes = Arrays.asList("anomaly-detector", "forecaster", "ml-model");
        RequestContentValidator.validateValueInSet(
            "resource_type",
            "anomaly-detector",
            RequestContentValidator.MAX_STRING_LENGTH,
            allowedTypes
        );
    }

    @Test
    public void testValidateValueInSetRejectsInvalidCharacters() {
        List<String> allowedTypes = List.of("anomaly-detector");
        String resourceType = "anomaly detector"; // contains space
        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.validateValueInSet(
                "resource_type",
                resourceType,
                RequestContentValidator.MAX_STRING_LENGTH,
                allowedTypes
            )
        );
    }

    @Test
    public void testValidateValueInSetRejectsWhenNoAllowedTypesConfiguredNull() {
        expectThrows(
            IllegalStateException.class,
            () -> RequestContentValidator.validateValueInSet(
                "resource_type",
                "anomaly-detector",
                RequestContentValidator.MAX_STRING_LENGTH,
                null
            )
        );
    }

    @Test
    public void testValidateValueInSetRejectsWhenNoAllowedTypesConfiguredEmpty() {
        expectThrows(
            IllegalStateException.class,
            () -> RequestContentValidator.validateValueInSet(
                "resource_type",
                "anomaly-detector",
                RequestContentValidator.MAX_STRING_LENGTH,
                Collections.emptyList()
            )
        );
    }

    @Test
    public void testValidateValueInSetRejectsWhenTypeNotInAllowedList() {
        List<String> allowedTypes = Arrays.asList("anomaly-detector", "forecaster");
        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.validateValueInSet(
                "resource_type",
                "ml-model",
                RequestContentValidator.MAX_STRING_LENGTH,
                allowedTypes
            )
        );
    }

    /* ---------------------- validateSafeValue (for principals) ---------------------- */

    @Test
    public void testValidateSafeValueAcceptsValidPrincipal() {
        RequestContentValidator.validateSafeValue("users", "user_123-role:1", RequestContentValidator.MAX_STRING_LENGTH);
    }

    /* ---------------------- validatePath (generic) ---------------------- */

    @Test
    public void testValidatePathAcceptsValidPath() {
        RequestContentValidator.validatePath("username_path", "user.details.name", RequestContentValidator.MAX_STRING_LENGTH);
    }

    @Test
    public void testValidatePathRejectsEmpty() {
        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.validatePath("username_path", "", RequestContentValidator.MAX_STRING_LENGTH)
        );
    }

    @Test
    public void testValidatePathRejectsWhitespace() {
        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.validatePath("username_path", " user . name ", RequestContentValidator.MAX_STRING_LENGTH)
        );
    }

    /* ---------------------- validateNameInSet (generic) ---------------------- */

    @Test
    public void testValidateFieldValueInSetAcceptsWhenInAllowedSet() {
        Set<String> allowed = new HashSet<>();
        allowed.add("index-1");
        allowed.add("index-2");

        RequestContentValidator.validateFieldValueInSet(
            "source_index",
            "index-1",
            RequestContentValidator.MAX_STRING_LENGTH,
            allowed,
            "indices"
        );
    }

    @Test
    public void testValidateFieldValueInSetRejectsWhenNotInAllowedSet() {
        Set<String> allowed = new HashSet<>();
        allowed.add("index-1");

        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.validateFieldValueInSet(
                "source_index",
                "index-2",
                RequestContentValidator.MAX_STRING_LENGTH,
                allowed,
                "indices"
            )
        );
    }

    @Test
    public void testValidateFieldValueInSetRejectsWhenNoNamesConfiguredNull() {
        expectThrows(
            IllegalStateException.class,
            () -> RequestContentValidator.validateFieldValueInSet(
                "source_index",
                "index-1",
                RequestContentValidator.MAX_STRING_LENGTH,
                null,
                "indices"
            )
        );
    }

    @Test
    public void testValidateFieldValueInSetRejectsWhenNoNamesConfiguredEmpty() {
        expectThrows(
            IllegalStateException.class,
            () -> RequestContentValidator.validateFieldValueInSet(
                "source_index",
                "index-1",
                RequestContentValidator.MAX_STRING_LENGTH,
                Collections.emptySet(),
                "indices"
            )
        );
    }

    /* ---------------------- validateObjectWithStringValues (generic) ---------------------- */

    @Test
    public void testValidateNonEmptyValuesInAnObjectAllowsNull() {
        // field absent / null is allowed (optional)
        RequestContentValidator.validateNonEmptyValuesInAnObject("default_access_level", null);
    }

    @Test
    public void testValidateObjectWithStringValuesRejectsNonObjectInAnObject() throws Exception {
        JsonNode node = DefaultObjectMapper.readTree("\"string-not-object\"");

        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.validateNonEmptyValuesInAnObject("default_access_level", node)
        );
    }

    @Test
    public void testValidateObjectWithStringValuesRejectsEmptyObjectInAnObject() throws Exception {
        JsonNode node = DefaultObjectMapper.readTree("{}");

        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.validateNonEmptyValuesInAnObject("default_access_level", node)
        );
    }

    @Test
    public void testValidateNonEmptyValuesInAnObjectRejectsEmptyValue() throws Exception {
        JsonNode node = DefaultObjectMapper.readTree("{\"anomaly-detector\":\"\"}");

        expectThrows(
            IllegalArgumentException.class,
            () -> RequestContentValidator.validateNonEmptyValuesInAnObject("default_access_level", node)
        );
    }

    @Test
    public void testValidateNonEmptyValuesAcceptsNonEmptyValuesInAnObject() throws Exception {
        JsonNode node = DefaultObjectMapper.readTree("{ \"anomaly-detector\": \"rd_read_only\", \"forecaster\": \"rd_write\" }");

        // should not throw
        RequestContentValidator.validateNonEmptyValuesInAnObject("default_access_level", node);
    }

}
