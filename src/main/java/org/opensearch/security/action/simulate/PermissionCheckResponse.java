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
package org.opensearch.security.action.simulate;

import java.io.IOException;
import java.util.Set;

import org.opensearch.common.xcontent.StatusToXContentObject;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

public class PermissionCheckResponse extends ActionResponse implements StatusToXContentObject {
    private final boolean accessAllowed;
    private final Set<String> missingPrivileges;

    public PermissionCheckResponse(boolean accessAllowed, Set<String> missingPrivileges) {
        this.accessAllowed = accessAllowed;
        this.missingPrivileges = missingPrivileges;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeBoolean(accessAllowed);
        out.writeStringCollection(missingPrivileges);
    }

    public PermissionCheckResponse(final StreamInput in) throws IOException {
        this.accessAllowed = in.readBoolean();
        this.missingPrivileges = in.readSet(StreamInput::readString);
    }

    @Override
    public RestStatus status() {
        return accessAllowed ? RestStatus.OK : RestStatus.FORBIDDEN;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        builder.startObject();
        builder.field("accessAllowed", accessAllowed);
        builder.field("missingPrivileges", missingPrivileges);
        builder.endObject();
        return builder;
    }
}
