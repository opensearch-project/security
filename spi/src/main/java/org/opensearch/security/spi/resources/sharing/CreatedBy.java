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
        return "CreatedBy {user='" + this.username + '\'' + '}';
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
        XContentParser.Token token;

        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                if (!"user".equals(parser.currentName())) {
                    throw new IllegalArgumentException("created_by must only contain a single field with user");
                }
            } else if (token == XContentParser.Token.VALUE_STRING) {
                username = parser.text();
            }
        }

        if (username == null) {
            throw new IllegalArgumentException("created_by cannot be empty");
        }

        return new CreatedBy(username);
    }
}
