/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.share;

import java.io.IOException;
import java.util.Arrays;

import org.opensearch.accesscontrol.resources.ShareWith;
import org.opensearch.accesscontrol.resources.SharedWithScope;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.sample.SampleResourceScope;

public class ShareResourceRequest extends ActionRequest {

    private final String resourceId;
    private final ShareWith shareWith;

    public ShareResourceRequest(String resourceId, ShareWith shareWith) {
        this.resourceId = resourceId;
        this.shareWith = shareWith;
    }

    public ShareResourceRequest(StreamInput in) throws IOException {
        this.resourceId = in.readString();
        this.shareWith = in.readNamedWriteable(ShareWith.class);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(resourceId);
        out.writeNamedWriteable(shareWith);
    }

    @Override
    public ActionRequestValidationException validate() {

        for (SharedWithScope s : shareWith.getSharedWithScopes()) {
            try {
                SampleResourceScope.valueOf(s.getScope());
            } catch (IllegalArgumentException | NullPointerException e) {
                ActionRequestValidationException exception = new ActionRequestValidationException();
                exception.addValidationError(
                    "Invalid scope: " + s.getScope() + ". Scope must be one of: " + Arrays.toString(SampleResourceScope.values())
                );
                return exception;
            }
            return null;
        }
        return null;
    }

    public String getResourceId() {
        return resourceId;
    }

    public ShareWith getShareWith() {
        return shareWith;
    }
}
