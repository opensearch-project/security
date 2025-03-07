/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources.sharing;

import java.io.IOException;

import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentFragment;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

/**
 * This class is used to store information about the creator of a resource.
 *
 * @opensearch.experimental
 */
public class CreatedBy implements ToXContentFragment, NamedWriteable {

    private final Creator creatorType;
    private final String creator;

    public CreatedBy(Creator creatorType, String creator) {
        this.creatorType = creatorType;
        this.creator = creator;
    }

    public CreatedBy(StreamInput in) throws IOException {
        this.creatorType = in.readEnum(Creator.class);
        this.creator = in.readString();
    }

    public String getCreator() {
        return creator;
    }

    public Creator getCreatorType() {
        return creatorType;
    }

    @Override
    public String toString() {
        return "CreatedBy {" + this.creatorType.getName() + "='" + this.creator + '\'' + '}';
    }

    @Override
    public String getWriteableName() {
        return "created_by";
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(Creator.valueOf(creatorType.name()));
        out.writeString(creator);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject().field(creatorType.getName(), creator).endObject();
    }

    public static CreatedBy fromXContent(XContentParser parser) throws IOException {
        String creator = null;
        Creator creatorType = null;
        XContentParser.Token token;

        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                creatorType = Creator.fromName(parser.currentName());
            } else if (token == XContentParser.Token.VALUE_STRING) {
                creator = parser.text();
            }
        }

        if (creator == null) {
            throw new IllegalArgumentException(creatorType + " is required");
        }

        return new CreatedBy(creatorType, creator);
    }
}
