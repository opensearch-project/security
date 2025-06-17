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
import org.opensearch.action.DocRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.spi.resources.sharing.ShareWith;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Request object for sharing sample resource transport action
 */
public class ShareResourceRequest extends ActionRequest implements DocRequest {

    private final String resourceId;

    private final ShareWith shareWithRecipients;

    public ShareResourceRequest(String resourceId, ShareWith shareWithRecipients) {
        this.resourceId = resourceId;
        this.shareWithRecipients = shareWithRecipients;
    }

    public ShareResourceRequest(StreamInput in) throws IOException {
        this.resourceId = in.readString();
        this.shareWithRecipients = new ShareWith(in);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(this.resourceId);
        shareWithRecipients.writeTo(out);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getResourceId() {
        return this.resourceId;
    }

    public ShareWith getShareWith() {
        return shareWithRecipients;
    }

    @Override
    public String index() {
        return RESOURCE_INDEX_NAME;
    }

    @Override
    public String id() {
        return resourceId;
    }
}
