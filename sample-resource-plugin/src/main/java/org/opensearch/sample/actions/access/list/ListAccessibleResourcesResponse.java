/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.access.list;

import java.io.IOException;
import java.util.List;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

/**
 * Response to a ListAccessibleResourcesRequest
 */
public class ListAccessibleResourcesResponse extends ActionResponse implements ToXContentObject {
    private final List<String> resourceIds;

    public ListAccessibleResourcesResponse(List<String> resourceIds) {
        this.resourceIds = resourceIds;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeStringArray(resourceIds.toArray(new String[0]));
    }

    public ListAccessibleResourcesResponse(final StreamInput in) throws IOException {
        resourceIds = in.readStringList();
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("resource-ids", resourceIds);
        builder.endObject();
        return builder;
    }
}
