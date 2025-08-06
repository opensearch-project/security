/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.api.share;

import java.io.IOException;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;

/**
 * This class is used to represent the response of a {@link ShareRequest}.
 *
 */
public class ShareResponse extends ActionResponse implements ToXContentObject {

    private final ResourceSharing resourceSharing;

    public ShareResponse(final StreamInput in) throws IOException {
        this.resourceSharing = in.readNamedWriteable(ResourceSharing.class);
    }

    public ShareResponse(ResourceSharing resourceSharing) {
        this.resourceSharing = resourceSharing;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeNamedWriteable(resourceSharing);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("sharing_info", resourceSharing);
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "ShareResponse [resourceSharing=" + resourceSharing + "]";
    }
}
