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

package org.opensearch.sample;

import java.io.IOException;
import java.util.Map;

import org.opensearch.accesscontrol.resources.Resource;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentBuilder;

public class SampleResource implements Resource {

    private String name;
    private String description;
    private Map<String, String> attributes;

    public SampleResource() {}

    public SampleResource(StreamInput in) throws IOException {
        this.name = in.readString();
        this.description = in.readString();
        this.attributes = in.readMap(StreamInput::readString, StreamInput::readString);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject().field("name", name).field("description", description).field("attributes", attributes).endObject();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeString(description);
        out.writeMap(attributes, StreamOutput::writeString, StreamOutput::writeString);
    }

    @Override
    public String getWriteableName() {
        return "sample_resource";
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getResourceName() {
        return name;
    }
}
