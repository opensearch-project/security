/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.rest.resources.access.list;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.spi.resources.Resource;

/**
 * Response to a ListAccessibleResourcesRequest
 */
public class ListAccessibleResourcesResponse extends ActionResponse implements ToXContentObject {
    private final Set<Resource> resources;

    public ListAccessibleResourcesResponse(Set<Resource> resources) {
        this.resources = resources;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(resources);
    }

    public ListAccessibleResourcesResponse(StreamInput in) {
        // TODO need to fix this to return correct value
        this.resources = new HashSet<>();
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("resources", resources);
        builder.endObject();
        return builder;
    }
}
