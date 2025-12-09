/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.sharing;

import java.io.IOException;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentFragment;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;

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
    public XContentBuilder toXContent(XContentBuilder b, Params params) throws IOException {
        b.startObject();
        for (Map.Entry<String, Recipients> e : this.sharingInfo.entrySet()) {
            Recipients norm = pruneRecipients(e.getValue());
            if (norm == null) continue; // skip empty level
            b.field(e.getKey());
            norm.toXContent(b, params); // TODO ensure this skips empty arrays too
        }
        return b.endObject();
    }

    /**
     * Parse ShareWith from XContent without validation
     */
    public static ShareWith fromXContent(XContentParser parser) throws IOException {
        return fromXContent(parser, null);
    }

    /**
     * Parse ShareWith from XContent with custom access level validator
     * @param parser the XContent parser
     * @param accessLevelValidator optional validator for access level field names (can be null)
     */
    public static ShareWith fromXContent(XContentParser parser, RequestContentValidator.FieldValidator accessLevelValidator)
        throws IOException {
        Map<String, Recipients> sharingInfo = new HashMap<>();

        if (parser.currentToken() != XContentParser.Token.START_OBJECT) {
            parser.nextToken();
        }

        XContentParser.Token token;
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            // Each field in the object represents a SharedWithActionGroup
            if (token == XContentParser.Token.FIELD_NAME) {
                String accessLevel = parser.currentName();

                // Validate access level if validator is provided
                if (accessLevelValidator != null) {
                    accessLevelValidator.validate("access_level", accessLevel);
                }

                parser.nextToken();

                Recipients recipients = Recipients.fromXContent(
                    parser,
                    RequestContentValidator.ARRAY_SIZE_VALIDATOR,
                    RequestContentValidator.principalValidator(false)
                );
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
        for (var entry : other.sharingInfo.entrySet()) {
            String level = entry.getKey();
            Recipients patchRecipients = entry.getValue();
            sharingInfo.merge(level, patchRecipients, (orig, patchRec) -> {
                orig.share(patchRec);
                return orig;
            });
        }
        return this;
    }

    /**
     * Returns a new ShareWith by revoking recipients based on another ShareWith.
     */
    public ShareWith revoke(ShareWith other) {
        if (this.sharingInfo.isEmpty() || other == null || other.isPrivate()) {
            return this;
        }
        for (var entry : other.sharingInfo.entrySet()) {
            String level = entry.getKey();
            Recipients toRevoke = entry.getValue();
            sharingInfo.computeIfPresent(level, (lvl, orig) -> {
                orig.revoke(toRevoke);
                return orig;
            });
        }
        return this;
    }

    /** Return a normalized ShareWith with no empty buckets and no empty action-groups. */
    public ShareWith prune() {
        Map<String, Recipients> cleaned = new HashMap<>();
        for (Map.Entry<String, Recipients> e : this.sharingInfo.entrySet()) {
            Recipients prunedRecipients = pruneRecipients(e.getValue());
            if (prunedRecipients != null) {
                cleaned.put(e.getKey(), prunedRecipients);
            }
        }
        return new ShareWith(cleaned);
    }

    private static Recipients pruneRecipients(Recipients r) {
        if (r == null) return null;
        Map<Recipient, Set<String>> src = r.getRecipients();
        if (src == null || src.isEmpty()) return null;

        Map<Recipient, Set<String>> cleaned = new EnumMap<>(Recipient.class);
        for (Map.Entry<Recipient, Set<String>> e : src.entrySet()) {
            Set<String> vals = e.getValue();
            if (vals == null) continue;
            Set<String> filtered = vals.stream()
                .filter(s -> s != null && !s.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
            if (!filtered.isEmpty()) cleaned.put(e.getKey(), filtered);
        }
        return cleaned.isEmpty() ? null : new Recipients(cleaned);
    }

}
