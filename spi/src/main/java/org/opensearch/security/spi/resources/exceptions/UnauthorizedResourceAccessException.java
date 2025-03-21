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

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.rest.RestStatus;

/**
 * This class represents an exception that occurs when an unauthorized user tries to access the resource.
 * It extends the ResourceSharingException class.
 *
 * @opensearch.experimental
 */
public final class UnauthorizedResourceAccessException extends ResourceSharingException {
    public UnauthorizedResourceAccessException(Throwable cause) {
        super(cause);
    }

    public UnauthorizedResourceAccessException(String msg, Object... args) {
        super(msg, args);
    }

    public UnauthorizedResourceAccessException(String msg, Throwable cause, Object... args) {
        super(msg, cause, args);
    }

    public UnauthorizedResourceAccessException(StreamInput in) throws IOException {
        super(in);
    }

    @Override
    public RestStatus status() {
        return RestStatus.FORBIDDEN;
    }
}
