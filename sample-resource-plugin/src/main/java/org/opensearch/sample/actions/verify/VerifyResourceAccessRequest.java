/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.verify;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

public class VerifyResourceAccessRequest extends ActionRequest {

    private final String resourceId;

    private final String sourceIdx;

    private final String scope;

    /**
     * Default constructor
     */
    public VerifyResourceAccessRequest(String resourceId, String sourceIdx, String scope) {
        this.resourceId = resourceId;
        this.sourceIdx = sourceIdx;
        this.scope = scope;
    }

    /**
     * Constructor with stream input
     * @param in the stream input
     * @throws IOException IOException
     */
    public VerifyResourceAccessRequest(final StreamInput in) throws IOException {
        this.resourceId = in.readString();
        this.sourceIdx = in.readString();
        this.scope = in.readString();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(resourceId);
        out.writeString(sourceIdx);
        out.writeString(scope);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getResourceId() {
        return resourceId;
    }

    public String getSourceIdx() {
        return sourceIdx;
    }

    public String getScope() {
        return scope;
    }
}
