/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.access.list;

import java.io.IOException;
import java.util.Set;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.sample.SampleResource;

/**
 * Response to a ListAccessibleResourcesRequest
 */
public class ListAccessibleResourcesResponse extends ActionResponse implements ToXContentObject {
    private final Set<SampleResource> resources;

    public ListAccessibleResourcesResponse(Set<SampleResource> resources) {
        this.resources = resources;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(resources);
    }

    public ListAccessibleResourcesResponse(final StreamInput in) throws IOException {
        this.resources = in.readSet(SampleResource::new);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("resources", resources);
        builder.endObject();
        return builder;
    }
}
