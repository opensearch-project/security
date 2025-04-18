/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources.sharing;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentFragment;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

/**
 * This class contains information about whom a resource is shared with and what is the action-group associated with it.
 *
 * <p>Example usage:
 * <pre>
 * "share_with": {
 *   "default": {
 *     "users": [],
 *     "roles": [],
 *     "backend_roles": []
 *   }
 * }
 * </pre>
 *
 * "default" is a place-holder {@link org.opensearch.security.spi.resources.ResourceAccessActionGroups#PLACE_HOLDER } that must be replaced with action-group names once Resource Authorization framework is implemented.
 *
 * @opensearch.experimental
 */

public class ShareWith implements ToXContentFragment, NamedWriteable {

    /**
     * A set of objects representing the action-groups and their associated users, roles, and backend roles.
     */
    private final Set<SharedWithActionGroup> sharedWithActionGroups;

    public ShareWith(Set<SharedWithActionGroup> sharedWithActionGroups) {
        this.sharedWithActionGroups = sharedWithActionGroups;
    }

    public ShareWith(StreamInput in) throws IOException {
        this.sharedWithActionGroups = in.readSet(SharedWithActionGroup::new);
    }

    public Set<SharedWithActionGroup> getSharedWithActionGroups() {
        return sharedWithActionGroups;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();

        for (SharedWithActionGroup actionGroup : sharedWithActionGroups) {
            actionGroup.toXContent(builder, params);
        }

        return builder.endObject();
    }

    public static ShareWith fromXContent(XContentParser parser) throws IOException {
        Set<SharedWithActionGroup> sharedWithActionGroups = new HashSet<>();

        if (parser.currentToken() != XContentParser.Token.START_OBJECT) {
            parser.nextToken();
        }

        XContentParser.Token token;
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            // Each field in the object represents a SharedWithActionGroup
            if (token == XContentParser.Token.FIELD_NAME) {
                SharedWithActionGroup actionGroup = SharedWithActionGroup.fromXContent(parser);
                sharedWithActionGroups.add(actionGroup);
            }
        }

        return new ShareWith(sharedWithActionGroups);
    }

    @Override
    public String getWriteableName() {
        return "share_with";
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(sharedWithActionGroups);
    }

    @Override
    public String toString() {
        return "ShareWith " + sharedWithActionGroups;
    }
}
