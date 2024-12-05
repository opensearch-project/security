/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.access.share;

import java.io.IOException;
import java.util.stream.Collectors;

import org.opensearch.accesscontrol.resources.ShareWith;
import org.opensearch.accesscontrol.resources.SharedWithScope;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.sample.utils.Validation;

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

        return Validation.validateScopes(
            shareWith.getSharedWithScopes().stream().map(SharedWithScope::getScope).collect(Collectors.toSet())
        );
    }

    public String getResourceId() {
        return resourceId;
    }

    public ShareWith getShareWith() {
        return shareWith;
    }
}
