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

import org.opensearch.core.ParseField;
import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ConstructingObjectParser;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import static org.opensearch.core.xcontent.ConstructingObjectParser.constructorArg;
import static org.opensearch.core.xcontent.ConstructingObjectParser.optionalConstructorArg;

/**
 * Sample resource declared by this plugin.
 */
public class SampleResource implements NamedWriteable, ToXContentObject {

    private String name;
    private String description;
    private Map<String, String> attributes;

    public SampleResource() throws IOException {
        super();
    }

    public SampleResource(StreamInput in) throws IOException {
        this.name = in.readString();
        this.description = in.readString();
        this.attributes = in.readMap(StreamInput::readString, StreamInput::readString);
    }

    private static final ConstructingObjectParser<SampleResource, Void> PARSER = new ConstructingObjectParser<>(
        "sample_resource",
        true,
        a -> {
            SampleResource s;
            try {
                s = new SampleResource();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            s.setName((String) a[0]);
            s.setDescription((String) a[1]);
            s.setAttributes((Map<String, String>) a[2]);
            return s;
        }
    );

    static {
        PARSER.declareString(constructorArg(), new ParseField("name"));
        PARSER.declareStringOrNull(optionalConstructorArg(), new ParseField("description"));
        PARSER.declareObjectOrNull(optionalConstructorArg(), (p, c) -> p.mapStrings(), null, new ParseField("attributes"));
    }

    public static SampleResource fromXContent(XContentParser parser) throws IOException {
        return PARSER.parse(parser, null);
    }

    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        return builder.startObject().field("name", name).field("description", description).field("attributes", attributes).endObject();
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeString(description);
        out.writeMap(attributes, StreamOutput::writeString, StreamOutput::writeString);
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

    public String getName() {
        return name;
    }

    @Override
    public String getWriteableName() {
        return "sample_resource";
    }
}
