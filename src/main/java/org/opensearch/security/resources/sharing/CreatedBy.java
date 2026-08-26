/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.sharing;

import java.io.IOException;

import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentFragment;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import static org.opensearch.core.xcontent.XContentParser.Token.VALUE_STRING;

/**
 * This class is used to store information about the creator of a resource.
 *
 * @opensearch.experimental
 */
public class CreatedBy implements ToXContentFragment, NamedWriteable {

    private final String username;

    public CreatedBy(String username) {
        this.username = username;
    }

    public CreatedBy(StreamInput in) throws IOException {
        this.username = in.readString();
    }

    public String getUsername() {
        return username;
    }

    @Override
    public String toString() {
        return """
            CreatedBy {user='%s'}
            """.formatted(username).trim();
    }

    @Override
    public String getWriteableName() {
        return "created_by";
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(username);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject().field("user", username).endObject();
    }

    public static CreatedBy fromXContent(XContentParser parser) throws IOException {
        String username = null;

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken() == XContentParser.Token.FIELD_NAME) {
                String fieldName = parser.currentName();
                parser.nextToken();

                switch (fieldName) {
                    case "user":
                        if (VALUE_STRING == parser.currentToken()) {
                            username = parser.text();
                        } else {
                            throw new IllegalArgumentException("created_by cannot be empty");
                        }
                        break;

                    default:
                        throw new IllegalArgumentException("created_by contains unknown field: " + fieldName);
                }
            }
        }

        if (username == null) {
            throw new IllegalArgumentException("created_by cannot be empty");
        }

        return new CreatedBy(username);
    }
}
