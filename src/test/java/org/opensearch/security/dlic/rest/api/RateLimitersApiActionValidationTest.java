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

package org.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.util.List;

import org.junit.Test;

import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.util.FakeRestRequest;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RateLimitersApiActionValidationTest extends AbstractApiActionValidationTest {

    @Test
    public void validateAllowedFields() throws IOException {
        final var authFailureListener = new ConfigV7.AuthFailureListener();

        final var content = DefaultObjectMapper.writeValueAsString(objectMapper.valueToTree(authFailureListener), false);

        var validResult = validate(content);
        assertTrue(validResult.isValid());

        final var invalidContent = objectMapper.createObjectNode()
            .set(
                "blah",
                objectMapper.createObjectNode()

            );

        var inValidResult = validate(invalidContent.toString());
        assertFalse(inValidResult.isValid());
        assertThat(inValidResult.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void validateIgnoreHostsElements() throws IOException {
        final ObjectNode validContent = objectMapper.createObjectNode().put("type", "ip");
        validContent.putArray("ignore_hosts").add("192.0.2.1").add("192.0.2.0/24").add("*.example.com");
        assertTrue(validate(validContent.toString()).isValid());

        final ObjectNode nonStringContent = objectMapper.createObjectNode().put("type", "ip");
        nonStringContent.putArray("ignore_hosts").add("192.0.2.1").add(42);
        assertInvalidField(nonStringContent, "ignore_hosts", "should only contain string values");
    }

    @Test
    public void rejectEnvironmentExpressionsInIgnoreHosts() throws IOException {
        for (String expression : List.of(
            "${env.IGNORED_HOST}",
            "${envbc.IGNORED_HOST}",
            "${envbase64.IGNORED_HOST}",
            "${envbase64:IGNORED_HOST}"
        )) {
            final ObjectNode content = objectMapper.createObjectNode().put("type", "ip");
            content.putArray("ignore_hosts").add(expression);
            assertInvalidField(content, "ignore_hosts", "must not contain environment variable expressions");
        }
    }

    @Test
    public void rejectInvalidNumericRanges() throws IOException {
        for (String field : List.of("time_window_seconds", "block_expiry_seconds", "max_blocked_clients", "max_tracked_clients")) {
            final ObjectNode content = objectMapper.createObjectNode().put("type", "ip").put(field, -1);
            assertInvalidField(content, field, "must be between 0 and");
        }

        final ObjectNode allowedTries = objectMapper.createObjectNode().put("type", "ip").put("allowed_tries", 0);
        assertInvalidField(allowedTries, "allowed_tries", "must be between 1 and");

        final ObjectNode outOfIntegerRange = objectMapper.createObjectNode().put("type", "ip").put("max_tracked_clients", 2_147_483_648L);
        assertInvalidField(outOfIntegerRange, "max_tracked_clients", "must be between 0 and 2147483647");
    }

    @Test
    public void acceptNumericBoundaryValues() throws IOException {
        final ObjectNode content = objectMapper.createObjectNode()
            .put("type", "ip")
            .put("allowed_tries", 1)
            .put("time_window_seconds", 0)
            .put("block_expiry_seconds", Integer.MAX_VALUE)
            .put("max_blocked_clients", 0)
            .put("max_tracked_clients", Integer.MAX_VALUE);

        assertTrue(validate(content.toString()).isValid());
    }

    private void assertInvalidField(ObjectNode content, String field, String expectedMessage) throws IOException {
        final ValidationResult<JsonNode> result = validate(content.toString());
        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
        assertThat(xContentToJsonNode(result.errorMessage()).get(field).asText(), containsString(expectedMessage));
    }

    private ValidationResult<JsonNode> validate(String content) throws IOException {
        final RequestContentValidator validator = new RateLimitersApiAction(clusterService, threadPool, securityApiDependencies)
            .createEndpointValidator()
            .createRequestContentValidator();
        return validator.validate(
            FakeRestRequest.builder()
                .withMethod(RestRequest.Method.PUT)
                .withPath("_plugins/_security/api/authfailurelisteners/test")
                .withContent(new BytesArray(content))
                .build()
        );
    }
}
