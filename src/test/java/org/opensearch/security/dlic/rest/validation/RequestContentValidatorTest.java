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
import java.util.Collections;
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

import static org.junit.Assert.assertEquals;
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
                    RequestContentValidator.DataType.ARRAY
                );
            }
        });

        final JsonNode payload = DefaultObjectMapper.objectMapper.createObjectNode().put("a", 1).put("b", "[]").put("c", "{}");
        when(httpRequest.content()).thenReturn(new BytesArray(payload.toString()));
        final ValidationResult<JsonNode> validationResult = validator.validate(request);

        final JsonNode errorMessage = xContentToJsonNode(validationResult.errorMessage());
        assertFalse(validationResult.isValid());
        assertErrorMessage(errorMessage, RequestContentValidator.ValidationError.WRONG_DATATYPE);

        assertEquals("String expected", errorMessage.get("a").asText());
        assertEquals("Object expected", errorMessage.get("b").asText());
        assertEquals("Array expected", errorMessage.get("c").asText());
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

        assertEquals("{\"keys\":\"c,d\"}", errorMessage.get("invalid_keys").toString());
        assertEquals("{\"keys\":\"a\"}", errorMessage.get("missing_mandatory_keys").toString());
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
                    RequestContentValidator.DataType.BOOLEAN
                );
            }
        });

        ObjectNode payload = DefaultObjectMapper.objectMapper.createObjectNode().putObject("a");
        payload.putArray("a").add("arrray");
        payload.put("b", true).put("d", "some_string").put("e", "true");
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
        assertEquals("error", jsonNode.get("status").asText());
        assertEquals(expectedValidationError.message(), jsonNode.get("reason").asText());
    }

}
