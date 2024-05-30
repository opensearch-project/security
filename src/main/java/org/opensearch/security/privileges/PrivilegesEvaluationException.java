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

import org.apache.commons.lang3.StringUtils;

/**
 * Signifies that an error was encountered while evaluating the privileges of a user for a particular request.
 *
 */
public class PrivilegesEvaluationException extends Exception {
    public PrivilegesEvaluationException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Returns a formatted multi-line-string showing cause messages as separate, indented lines. Does not include
     * stack traces.
     */
    public String getNestedMessages() {
        if (this.getCause() == null) {
            return this.getMessage();
        }

        StringBuilder result = new StringBuilder(this.getMessage()).append("\n");

        Throwable cause = this.getCause();
        for (int i = 1; cause != null; cause = cause.getCause(), i++) {
            result.append(StringUtils.repeat(' ', i * 3)).append(cause.getMessage()).append("\n");
        }

        return result.toString();
    }
}
