/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest.list;

import java.io.IOException;
import java.util.Set;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.spi.resources.ShareableResource;

/**
 * This class is used to represent the response of a {@link ListAccessibleResourcesRequest}.
 *
 * @opensearch.experimental
 */
public class ListAccessibleResourcesResponse extends ActionResponse implements ToXContentObject {

    private final Set<ShareableResource> resources;

    @SuppressWarnings("unchecked")
    public ListAccessibleResourcesResponse(final StreamInput in) throws IOException {
        this.resources = (Set<ShareableResource>) in.readGenericValue();
    }

    public ListAccessibleResourcesResponse(Set<ShareableResource> shareableResources) {
        this.resources = shareableResources;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(resources);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("resources", resources);
        return builder.endObject();
    }

    public Set<ShareableResource> getResources() {
        return resources;
    }

    @Override
    public String toString() {
        return "ListAccessibleResourcesResponse [resources=" + resources + "]";
    }
}
