package org.opensearch.security.spi.resources;

import java.io.IOException;

import org.opensearch.OpenSearchException;
import org.opensearch.core.common.io.stream.StreamInput;

/**
 * This class represents an exception that occurs during resource sharing operations.
 * It extends the OpenSearchException class.
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
}
