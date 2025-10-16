/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.get;

import java.io.IOException;
import java.util.Set;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.sample.SampleResource;

public class GetResourceGroupResponse extends ActionResponse implements ToXContentObject {
    private final Set<SampleResource> resources;

    /**
     * Default constructor
     *
     * @param resources The resources
     */
    public GetResourceGroupResponse(Set<SampleResource> resources) {
        this.resources = resources;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(resources, (o, r) -> r.writeTo(o));
    }

    /**
     * Constructor with StreamInput
     *
     * @param in the stream input
     */
    public GetResourceGroupResponse(final StreamInput in) throws IOException {
        resources = in.readSet(SampleResource::new);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("resources", resources);
        builder.endObject();
        return builder;
    }
}
