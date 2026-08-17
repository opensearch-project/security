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
import java.util.Map;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.tasks.TaskId;
import org.opensearch.tasks.Task;

/**
 * Request carrying everything required to persist a serialized Security configuration to the
 * security index and then fan out a reload to all nodes.
 *
 * <p>The task created for this request is intentionally a plain {@link Task} (not a {@link
 * org.opensearch.tasks.CancellableTask}), so {@code POST /_tasks/{id}/_cancel} against it is
 * rejected by {@code TransportCancelTasksAction} with {@code "doesn't support cancellation"}.
 */
public class SecurityConfigWriteRequest extends ActionRequest {

    private final String cType;
    private final BytesReference content;
    private final long seqNo;
    private final long primaryTerm;
    private final String securityIndex;
    private final String description;
    private final String successMessage;
    private final RestStatus successStatus;

    public SecurityConfigWriteRequest(
        final String cType,
        final BytesReference content,
        final long seqNo,
        final long primaryTerm,
        final String securityIndex,
        final String description,
        final String successMessage,
        final RestStatus successStatus
    ) {
        this.cType = cType;
        this.content = content;
        this.seqNo = seqNo;
        this.primaryTerm = primaryTerm;
        this.securityIndex = securityIndex;
        this.description = description == null ? "" : description;
        this.successMessage = successMessage;
        this.successStatus = successStatus;
    }

    public SecurityConfigWriteRequest(final StreamInput in) throws IOException {
        super(in);
        this.cType = in.readString();
        this.content = in.readBytesReference();
        this.seqNo = in.readLong();
        this.primaryTerm = in.readLong();
        this.securityIndex = in.readString();
        this.description = in.readString();
        this.successMessage = in.readString();
        this.successStatus = in.readEnum(RestStatus.class);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(cType);
        out.writeBytesReference(content);
        out.writeLong(seqNo);
        out.writeLong(primaryTerm);
        out.writeString(securityIndex);
        out.writeString(description);
        out.writeString(successMessage);
        out.writeEnum(successStatus);
    }

    @Override
    public ActionRequestValidationException validate() {
        // Defer to server-side validation on the actual index write; there are no cheap client-side
        // preconditions worth checking here beyond non-null fields, which the constructor enforces
        // implicitly by producing an unusable request if any are null.
        if (Strings.isNullOrEmpty(cType) || content == null || Strings.isNullOrEmpty(securityIndex) || successStatus == null) {
            final var e = new ActionRequestValidationException();
            e.addValidationError("cType, content, securityIndex and successStatus are required");
            return e;
        }
        return null;
    }

    @Override
    public boolean getShouldStoreResult() {
        // Always true: this request is only submitted from the async pre-branch in
        // AbstractApiAction, where the whole point is to make the outcome retrievable later via
        // GET /_tasks/{id}. Sync writes never reach this code path.
        return true;
    }

    @Override
    public Task createTask(
        final long id,
        final String type,
        final String action,
        final TaskId parentTaskId,
        final Map<String, String> headers
    ) {
        // Plain Task on purpose — see class-level Javadoc for why cancellation is not supported.
        return new Task(id, type, action, getDescription(), parentTaskId, headers);
    }

    @Override
    public String getDescription() {
        return description;
    }

    public String getCType() {
        return cType;
    }

    public BytesReference getContent() {
        return content;
    }

    public long getSeqNo() {
        return seqNo;
    }

    public long getPrimaryTerm() {
        return primaryTerm;
    }

    public String getSecurityIndex() {
        return securityIndex;
    }

    public String getSuccessMessage() {
        return successMessage;
    }

    public RestStatus getSuccessStatus() {
        return successStatus;
    }
}
