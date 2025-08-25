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
    private final String tenant; // capture tenant if multi-tenancy is enabled

    public CreatedBy(String username) {
        this.username = username;
        this.tenant = null;
    }

    public CreatedBy(String username, String tenant) {
        this.username = username;
        this.tenant = tenant;
    }

    public CreatedBy(StreamInput in) throws IOException {
        this.username = in.readString();
        this.tenant = in.readOptionalString();
    }

    public String getUsername() {
        return username;
    }

    public String getTenant() {
        return tenant;
    }

    @Override
    public String toString() {
        if (tenant != null) {
            return """
                CreatedBy {user='%s', tenant='%s'}
                """.formatted(username, tenant).trim();
        }
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
        out.writeOptionalString(tenant);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        if (tenant != null) {
            return builder.startObject().field("user", username).field("tenant", tenant).endObject();
        }
        return builder.startObject().field("user", username).endObject();
    }

    public static CreatedBy fromXContent(XContentParser parser) throws IOException {
        String username = null;
        String tenant = null;
        XContentParser.Token token;

        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                String fieldName = parser.currentName();
                if ("user".equals(fieldName)) {
                    parser.nextToken();
                    username = parser.text();
                } else if ("tenant".equals(fieldName)) {
                    parser.nextToken();
                    tenant = parser.text();
                } else {
                    throw new IllegalArgumentException("created_by contains unknown field: " + fieldName);
                }
            }
        }

        if (username == null) {
            throw new IllegalArgumentException("created_by cannot be empty");
        }

        return new CreatedBy(username, tenant);
    }
}
