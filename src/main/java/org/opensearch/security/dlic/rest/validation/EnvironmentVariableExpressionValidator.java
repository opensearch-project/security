/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.dlic.rest.validation;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonToken;

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
            try (var parser = DefaultObjectMapper.objectMapper().createParser(request.content().utf8ToString())) {
                // Jackson handles nesting and escapes for both property names and string values.
                JsonToken token;
                while ((token = parser.nextToken()) != null) {
                    if ((token == JsonToken.PROPERTY_NAME || token == JsonToken.VALUE_STRING) && containsExpression(parser.getString())) {
                        return rejected();
                    }
                }
            } catch (JacksonException e) {
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

    private static boolean containsExpression(String value) {
        // Include malformed forms as well as supported environment substitution syntax.
        return value != null && value.contains("${env");
    }

    private static ValidationResult<RestRequest> rejected() {
        // Do not echo potentially sensitive request content or attempt substitution.
        return ValidationResult.error(
            RestStatus.BAD_REQUEST,
            badRequestMessage("Security API request bodies and parameters must not contain environment variable expressions")
        );
    }
}
