/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources.sharing;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
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
 * @opensearch.experimental
 */

public class ShareWith implements ToXContentFragment, NamedWriteable {

    /**
     * A set of objects representing the action-groups and their associated users, roles, and backend roles.
     */
    private final Map<String, Recipients> sharingInfo;

    public ShareWith(Map<String, Recipients> sharingInfo) {
        this.sharingInfo = sharingInfo;
    }

    public ShareWith(StreamInput in) throws IOException {
        this.sharingInfo = in.readMap(StreamInput::readString, Recipients::new);
    }

    public boolean isPublic() {
        // TODO Contemplate following google doc model of link sharing which has single access level when link sharing is enabled
        return sharingInfo.values().stream().anyMatch(Recipients::isPublic);
    }

    public boolean isPrivate() {
        return sharingInfo == null || sharingInfo.isEmpty();
    }

    public Set<String> accessLevels() {
        return sharingInfo.keySet();
    }

    public Map<String, Recipients> getSharingInfo() {
        return sharingInfo;
    }

    public Recipients atAccessLevel(String accessLevel) {
        return sharingInfo.get(accessLevel);
    }

    /**
     * Adds a new entry in the sharingInfo map and returns the current object
     */
    public ShareWith updateSharingInfo(String accessLevel, Recipients target) {
        sharingInfo.put(accessLevel, target);
        return this;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();

        for (String accessLevel : sharingInfo.keySet()) {
            builder.field(accessLevel);
            Recipients recipients = sharingInfo.get(accessLevel);
            recipients.toXContent(builder, params);
        }

        return builder.endObject();
    }

    public static ShareWith fromXContent(XContentParser parser) throws IOException {
        Map<String, Recipients> sharingInfo = new HashMap<>();

        if (parser.currentToken() != XContentParser.Token.START_OBJECT) {
            parser.nextToken();
        }

        XContentParser.Token token;
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            // Each field in the object represents a SharedWithActionGroup
            if (token == XContentParser.Token.FIELD_NAME) {
                String accessLevel = parser.currentName();

                parser.nextToken();

                Recipients recipients = Recipients.fromXContent(parser);
                sharingInfo.put(accessLevel, recipients);
            }
        }

        return new ShareWith(sharingInfo);
    }

    @Override
    public String getWriteableName() {
        return "share_with";
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeMap(sharingInfo, StreamOutput::writeString, (o, sw) -> sw.writeTo(o));
    }

    @Override
    public String toString() {
        return "ShareWith " + sharingInfo;
    }

    /**
     * Returns a new ShareWith by merging this and another ShareWith (adding recipients).
     */
    public ShareWith add(ShareWith other) {
        if (other == null || other.isPrivate()) {
            return this;
        }
        Map<String, Recipients> updated = new HashMap<>(this.sharingInfo);
        for (var entry : other.sharingInfo.entrySet()) {
            String level = entry.getKey();
            Recipients patchRecipients = entry.getValue();
            updated.merge(level, patchRecipients, (orig, patchRec) -> {
                orig.share(patchRec);
                return orig;
            });
        }
        return new ShareWith(updated);
    }

    /**
     * Returns a new ShareWith by revoking recipients based on another ShareWith.
     */
    public ShareWith revoke(ShareWith other) {
        if (other == null || other.isPrivate()) {
            return this;
        }
        Map<String, Recipients> updated = new HashMap<>(this.sharingInfo);
        for (var entry : other.sharingInfo.entrySet()) {
            String level = entry.getKey();
            Recipients revokeRecipients = entry.getValue();
            updated.computeIfPresent(level, (lvl, orig) -> {
                orig.revoke(revokeRecipients);
                return orig;
            });
        }
        return new ShareWith(updated);
    }
}
