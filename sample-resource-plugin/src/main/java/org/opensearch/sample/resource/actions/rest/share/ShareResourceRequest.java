/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.share;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.spi.resources.sharing.SharedWithActionGroup;

/**
 * Request object for sharing sample resource transport action
 */
public class ShareResourceRequest extends ActionRequest {

    private final String resourceId;

    private final SharedWithActionGroup.ActionGroupRecipients shareWith;

    public ShareResourceRequest(String resourceId, SharedWithActionGroup.ActionGroupRecipients shareWith) {
        this.resourceId = resourceId;
        this.shareWith = shareWith;
    }

    public ShareResourceRequest(StreamInput in) throws IOException {
        this.resourceId = in.readString();
        this.shareWith = in.readNamedWriteable(SharedWithActionGroup.ActionGroupRecipients.class);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(this.resourceId);
        out.writeNamedWriteable(shareWith);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getResourceId() {
        return this.resourceId;
    }

    public SharedWithActionGroup.ActionGroupRecipients getShareWith() {
        return shareWith;
    }
}
