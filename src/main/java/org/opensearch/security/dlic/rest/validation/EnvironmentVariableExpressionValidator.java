/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.dlic.rest.validation;

import java.io.IOException;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;

import tools.jackson.databind.JsonNode;

import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;

/** Rejects REST-supplied environment expressions before configuration is persisted and reloaded. */
public final class EnvironmentVariableExpressionValidator {
    private EnvironmentVariableExpressionValidator() {}

    public static ValidationResult<RestRequest> validate(RestRequest request) {
        if (request.method() != RestRequest.Method.PUT
            && request.method() != RestRequest.Method.PATCH
            && request.method() != RestRequest.Method.POST) {
            // Reads and deletes must remain available to inspect or remove existing configuration.
            return ValidationResult.success(request);
        }
        for (var parameter : request.params().entrySet()) {
            if (containsExpression(parameter.getKey()) || containsExpression(parameter.getValue())) {
                return rejected();
            }
        }
        if (request.hasContent()) {
            try {
                // Inspect decoded keys and values, including JSON escapes and JSON Patch paths.
                if (containsExpression(DefaultObjectMapper.readTree(request.content().utf8ToString()))) {
                    return rejected();
                }
            } catch (IOException e) {
                return ValidationResult.error(
                    RestStatus.BAD_REQUEST,
                    (builder, params) -> builder.startObject()
                        .field("status", "error")
                        .field("reason", RequestContentValidator.ValidationError.BODY_NOT_PARSEABLE.message())
                        .endObject()
                );
            }
        }
        return ValidationResult.success(request);
    }

    public static boolean containsExpression(String value) {
        // Include malformed forms, matching the existing auth-failure-listener validation.
        return value != null && value.contains("${env");
    }

    private static boolean containsExpression(JsonNode node) {
        if (node == null) {
            return false;
        }
        if (node.isTextual()) {
            return containsExpression(node.asText());
        }
        if (node.isObject()) {
            for (var property : node.properties()) {
                if (containsExpression(property.getKey()) || containsExpression(property.getValue())) {
                    return true;
                }
            }
        } else if (node.isArray()) {
            for (JsonNode element : node) {
                if (containsExpression(element)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static ValidationResult<RestRequest> rejected() {
        // Do not echo potentially sensitive request content or attempt substitution.
        return ValidationResult.error(
            RestStatus.BAD_REQUEST,
            badRequestMessage("Security API request bodies and parameters must not contain environment variable expressions")
        );
    }
}
