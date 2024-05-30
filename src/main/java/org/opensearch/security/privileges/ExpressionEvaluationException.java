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
package org.opensearch.security.privileges;

/**
 * This exception indicates that an expression - such as a regular expression - could not be properly evaluated during
 * privilege evaluation.
 */
public class ExpressionEvaluationException extends Exception {
    public ExpressionEvaluationException(String message, Throwable cause) {
        super(message, cause);
    }
}
