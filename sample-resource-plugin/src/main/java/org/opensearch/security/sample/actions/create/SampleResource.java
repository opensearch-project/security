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

package org.opensearch.security.sample.actions.create;

import java.io.IOException;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.sample.Resource;

import static org.opensearch.security.sample.SampleResourcePlugin.RESOURCE_INDEX_NAME;

public class SampleResource extends Resource {

    private String name;

    public SampleResource() {}

    SampleResource(StreamInput in) throws IOException {
        this.name = in.readString();
    }

    @Override
    public String getResourceIndex() {
        return RESOURCE_INDEX_NAME;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject().field("name", name).endObject();
    }

    @Override
    public void writeTo(StreamOutput streamOutput) throws IOException {
        streamOutput.writeString(name);
    }

    @Override
    public String getWriteableName() {
        return "sampled_resource";
    }

    public void setName(String name) {
        this.name = name;
    }
}
