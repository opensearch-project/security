/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.revoke;

import java.io.IOException;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.spi.resources.sharing.ShareWith;

/**
 * Response for the RevokeResourceAccessAction
 */
public class RevokeResourceAccessResponse extends ActionResponse implements ToXContentObject {
    private final ShareWith shareWith;

    public RevokeResourceAccessResponse(ShareWith shareWith) {
        this.shareWith = shareWith;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeNamedWriteable(shareWith);
    }

    public RevokeResourceAccessResponse(final StreamInput in) throws IOException {
        shareWith = new ShareWith(in);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("share_with", shareWith);
        builder.endObject();
        return builder;
    }
}
