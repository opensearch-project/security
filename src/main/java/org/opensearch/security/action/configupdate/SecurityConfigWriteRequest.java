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
import java.util.Objects;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.tasks.TaskId;
import org.opensearch.tasks.Task;

/**
 * Request carrying everything required to persist a Security configuration document and fan out a
 * reload to all nodes. Deliberately carries a fully-built {@link IndexRequest} (constructed on the
 * coordinator via {@code AbstractApiAction.createIndexRequestForConfig}) rather than raw bytes, so
 * no builder logic is duplicated between the sync path and this transport action.
 *
 * <p>The task created for this request is intentionally a plain {@link Task} — see
 * {@link SecurityConfigWriteAction} for why cancellation is not supported.
 */
public class SecurityConfigWriteRequest extends ActionRequest {

    private final IndexRequest indexRequest;
    private final String cType;
    private final String description;
    private final String successMessage;
    private final RestStatus successStatus;

    public SecurityConfigWriteRequest(
        final IndexRequest indexRequest,
        final String cType,
        final String description,
        final String successMessage,
        final RestStatus successStatus
    ) {
        this.indexRequest = Objects.requireNonNull(indexRequest, "indexRequest must not be null");
        this.cType = Objects.requireNonNull(cType, "cType must not be null");
        this.description = description == null ? "" : description;
        this.successMessage = Objects.requireNonNull(successMessage, "successMessage must not be null");
        this.successStatus = Objects.requireNonNull(successStatus, "successStatus must not be null");
    }

    public SecurityConfigWriteRequest(final StreamInput in) throws IOException {
        super(in);
        this.indexRequest = new IndexRequest(in);
        this.cType = in.readString();
        this.description = in.readString();
        this.successMessage = in.readString();
        this.successStatus = in.readEnum(RestStatus.class);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        // TransportRequest.writeTo writes the parent task id — must be called for symmetry with
        // the StreamInput ctor's super(in) (which reads it back).
        super.writeTo(out);
        indexRequest.writeTo(out);
        out.writeString(cType);
        out.writeString(description);
        out.writeString(successMessage);
        out.writeEnum(successStatus);
    }

    @Override
    public ActionRequestValidationException validate() {
        if (Strings.isNullOrEmpty(cType)) {
            final var e = new ActionRequestValidationException();
            e.addValidationError("cType is required");
            return e;
        }
        // Defer index-side preconditions to indexRequest.validate() on the receiving node.
        return indexRequest.validate();
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
        // Plain Task on purpose — see SecurityConfigWriteAction class-level docs for why
        // cancellation is not supported.
        return new Task(id, type, action, getDescription(), parentTaskId, headers);
    }

    @Override
    public String getDescription() {
        return description;
    }

    public IndexRequest getIndexRequest() {
        return indexRequest;
    }

    public String getCType() {
        return cType;
    }

    public String getSuccessMessage() {
        return successMessage;
    }

    public RestStatus getSuccessStatus() {
        return successStatus;
    }
}
