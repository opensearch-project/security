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

package org.opensearch.security.spi.resources.exceptions;

import java.io.IOException;

import org.opensearch.OpenSearchException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.rest.RestStatus;

/**
 * This class represents an exception that occurs during resource sharing operations.
 * It extends the OpenSearchException class.
 *
 * @opensearch.experimental
 */
public class ResourceSharingException extends OpenSearchException {
    public ResourceSharingException(Throwable cause) {
        super(cause);
    }

    public ResourceSharingException(String msg, Object... args) {
        super(msg, args);
    }

    public ResourceSharingException(String msg, Throwable cause, Object... args) {
        super(msg, cause, args);
    }

    public ResourceSharingException(StreamInput in) throws IOException {
        super(in);
    }

    @Override
    public RestStatus status() {
        String message = getMessage();
        if (message.contains("not authorized")) {
            return RestStatus.FORBIDDEN;
        } else if (message.startsWith("No authenticated")) {
            return RestStatus.UNAUTHORIZED;
        } else if (message.contains("not found")) {
            return RestStatus.NOT_FOUND;
        } else if (message.contains("not a system index")) {
            return RestStatus.BAD_REQUEST;
        } else if (message.contains("is disabled")) {
            return RestStatus.NOT_IMPLEMENTED;
        }

        return RestStatus.INTERNAL_SERVER_ERROR;
    }
}
