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
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.opensearch.common.CheckedBiConsumer;
import org.opensearch.common.CheckedConsumer;
import org.opensearch.common.CheckedFunction;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;

public class ValidationResult<C> {

    private final RestStatus status;

    private final C content;

    private final ToXContent errorMessage;

    private ValidationResult(final C jsonContent) {
        this(RestStatus.OK, jsonContent, null);
    }

    private ValidationResult(final RestStatus status, final ToXContent errorMessage) {
        this(status, null, errorMessage);
    }

    private ValidationResult(final RestStatus status, final C jsonContent, final ToXContent errorMessage) {
        this.status = status;
        this.content = jsonContent;
        this.errorMessage = errorMessage;
    }

    public static <L> ValidationResult<L> success(final L content) {
        return new ValidationResult<>(content);
    }

    public static <L> ValidationResult<L> error(final RestStatus status, final ToXContent errorMessage) {
        return new ValidationResult<>(status, errorMessage);
    }

    /**
     * Transforms a list of validation results into a single validation result of that lists contents.
     * If any of the validation results are not valid, the first is returned as the error.
     */
    public static <L> ValidationResult<List<L>> merge(final List<ValidationResult<L>> results) {
        if (results.stream().allMatch(ValidationResult::isValid)) {
            return success(results.stream().map(result -> result.content).collect(Collectors.toList()));
        }

        return results.stream()
            .filter(result -> !result.isValid())
            .map(failedResult -> new ValidationResult<List<L>>(failedResult.status, failedResult.errorMessage))
            .findFirst()
            .get();
    }

    public <L> ValidationResult<L> map(final CheckedFunction<C, ValidationResult<L>, IOException> mapper) throws IOException {
        if (content != null) {
            return Objects.requireNonNull(mapper).apply(content);
        } else {
            return ValidationResult.error(status, errorMessage);
        }
    }

    public void error(final CheckedBiConsumer<RestStatus, ToXContent, IOException> mapper) throws IOException {
        if (errorMessage != null) {
            Objects.requireNonNull(mapper).accept(status, errorMessage);
        }
    }

    public ValidationResult<C> valid(final CheckedConsumer<C, IOException> mapper) throws IOException {
        if (content != null) {
            Objects.requireNonNull(mapper).accept(content);
        }
        return this;
    }

    public RestStatus status() {
        return status;
    }

    public boolean isValid() {
        return errorMessage == null;
    }

    public ToXContent errorMessage() {
        return errorMessage;
    }
}
