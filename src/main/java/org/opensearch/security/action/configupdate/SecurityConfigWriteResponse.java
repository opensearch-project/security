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

package org.opensearch.security.action.configupdate;

import java.io.IOException;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

/**
 * Response returned by {@link SecurityConfigWriteAction}. Body shape matches the message emitted
 * by the pre-existing synchronous save path (see {@code Responses.payload}):
 *
 * <pre>{@code
 * {
 *   "status": "CREATED"|"OK",
 *   "message": "'my_role' created."
 * }
 * }</pre>
 *
 * <p>Deliberately does not include configuration contents. When the task result is stored in
 * {@code .tasks} (via {@code setShouldStoreResult(true)} on the async path), only the values above
 * are persisted, so standard {@code _tasks} authorization is sufficient to satisfy the "do not
 * expose Security configuration contents" acceptance criterion from issue #6337.
 */
public class SecurityConfigWriteResponse extends ActionResponse implements ToXContentObject {

    private final RestStatus status;
    private final String message;

    public SecurityConfigWriteResponse(final RestStatus status, final String message) {
        this.status = status;
        this.message = message;
    }

    public SecurityConfigWriteResponse(final StreamInput in) throws IOException {
        super(in);
        this.status = in.readEnum(RestStatus.class);
        this.message = in.readString();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeEnum(status);
        out.writeString(message);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject();
        builder.field("status", status.name());
        builder.field("message", message);
        builder.endObject();
        return builder;
    }

    public RestStatus getStatus() {
        return status;
    }

    public String getMessage() {
        return message;
    }
}
