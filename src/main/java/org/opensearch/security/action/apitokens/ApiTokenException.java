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

package org.opensearch.security.action.apitokens;

import org.opensearch.OpenSearchException;

public class ApiTokenException extends OpenSearchException {
    public ApiTokenException(String message) {
        super(message);
    }

    public ApiTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
