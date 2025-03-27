/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest.verify;

import java.io.IOException;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

/**
 * This class is used to represent the response of a {@link VerifyResourceAccessRequest}
 *
 * @opensearch.experimental
 */
public class VerifyResourceAccessResponse extends ActionResponse implements ToXContentObject {
    private final boolean hasPermission;

    public VerifyResourceAccessResponse(final StreamInput in) throws IOException {
        this.hasPermission = in.readBoolean();
    }

    public VerifyResourceAccessResponse(boolean hasPermission) {
        this.hasPermission = hasPermission;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeBoolean(hasPermission);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("has_permission", hasPermission);
        return builder.endObject();
    }

    public Boolean getHasPermission() {
        return hasPermission;
    }

    @Override
    public String toString() {
        return "VerifyResourceAccessResponse [hasPermission=" + hasPermission + "]";
    }
}
