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

import com.fasterxml.jackson.databind.JsonNode;
import org.opensearch.common.CheckedConsumer;
import org.opensearch.common.CheckedFunction;
import org.opensearch.core.xcontent.ToXContent;

import java.io.IOException;
import java.util.Objects;

public class ValidationResult {

    private final JsonNode jsonContent;

    private final ToXContent errorMessage;

    private ValidationResult(final JsonNode jsonContent, final ToXContent errorMessage) {
        this.jsonContent = jsonContent;
        this.errorMessage = errorMessage;
    }

    public static ValidationResult success(final JsonNode jsonContent) {
        return new ValidationResult(jsonContent, null);
    }

    public static ValidationResult error(final ToXContent errorMessage) {
        return new ValidationResult(null, errorMessage);
    }

    public ValidationResult map(final CheckedFunction<JsonNode, ValidationResult, IOException> validation) throws IOException {
        if (jsonContent != null) {
            return Objects.requireNonNull(validation).apply(jsonContent);
        } else {
            return this;
        }
    }

    public void error(final CheckedConsumer<ToXContent, IOException> invalid) throws IOException {
        if (errorMessage != null) {
            Objects.requireNonNull(invalid).accept(errorMessage);
        }
    }

    public ValidationResult valid(final CheckedConsumer<JsonNode, IOException> contentHandler) throws IOException {
        if (jsonContent != null) {
            Objects.requireNonNull(contentHandler).accept(jsonContent);
        }
        return this;
    }

    public boolean isValid() {
        return errorMessage == null;
    }

    public ToXContent errorMessage() {
        return errorMessage;
    }

}
