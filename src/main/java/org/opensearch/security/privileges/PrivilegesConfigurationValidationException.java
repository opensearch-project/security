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
 * Thrown when the privileges configuration cannot be parsed because it is invalid.
 */
public class PrivilegesConfigurationValidationException extends Exception {
    public PrivilegesConfigurationValidationException(String message) {
        super(message);
    }

    public PrivilegesConfigurationValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
