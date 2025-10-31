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

import org.opensearch.core.ParseField;
import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ConstructingObjectParser;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import static org.opensearch.core.xcontent.ConstructingObjectParser.constructorArg;
import static org.opensearch.core.xcontent.ConstructingObjectParser.optionalConstructorArg;
import static org.opensearch.sample.utils.Constants.RESOURCE_GROUP_TYPE;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;

/**
 * Sample resource group declared by this plugin.
 */
public class SampleResourceGroup implements NamedWriteable, ToXContentObject {

    private String name;
    private String description;

    public SampleResourceGroup() throws IOException {
        super();
    }

    public SampleResourceGroup(StreamInput in) throws IOException {
        this.name = in.readString();
        this.description = in.readString();
    }

    private static final ConstructingObjectParser<SampleResourceGroup, Void> PARSER = new ConstructingObjectParser<>(
        RESOURCE_TYPE,
        true,
        a -> {
            SampleResourceGroup s;
            try {
                s = new SampleResourceGroup();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            s.setName((String) a[0]);
            s.setDescription((String) a[1]);
            return s;
        }
    );

    static {
        PARSER.declareString(constructorArg(), new ParseField("name"));
        PARSER.declareStringOrNull(optionalConstructorArg(), new ParseField("description"));
    }

    public static SampleResourceGroup fromXContent(XContentParser parser) throws IOException {
        return PARSER.parse(parser, null);
    }

    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
            .field("name", name)
            .field("description", description)
            .field("resource_type", RESOURCE_GROUP_TYPE)
            .endObject();
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeString(description);
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getName() {
        return name;
    }

    @Override
    public String getWriteableName() {
        return RESOURCE_GROUP_TYPE;
    }
}
