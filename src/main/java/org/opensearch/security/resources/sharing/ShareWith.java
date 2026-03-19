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

    /**
     * The access level granted to everyone (general/public access).
     * e.g. "read" means anyone can read; named recipients may hold higher levels.
     * Null means the resource is not publicly accessible.
     */
    private final String generalAccess;

    public ShareWith(Map<String, Recipients> sharingInfo) {
        this(sharingInfo, null);
    }

    public ShareWith(Map<String, Recipients> sharingInfo, String generalAccess) {
        this.sharingInfo = sharingInfo;
        this.generalAccess = generalAccess;
    }

    public ShareWith(StreamInput in) throws IOException {
        this.sharingInfo = in.readMap(StreamInput::readString, Recipients::new);
        this.generalAccess = in.readOptionalString();
    }

    public boolean isPublic() {
        return generalAccess != null;
    }

    public String getGeneralAccess() {
        return generalAccess;
    }

    public boolean isPrivate() {
        return generalAccess == null && (sharingInfo == null || sharingInfo.isEmpty());
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
        if (generalAccess != null) {
            b.field("general_access", generalAccess);
        }
        for (Map.Entry<String, Recipients> e : this.sharingInfo.entrySet()) {
            Recipients norm = pruneRecipients(e.getValue());
            if (norm == null) continue; // skip empty level
            b.field(e.getKey());
            norm.toXContent(b, params);
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

        String generalAccess = null;

        XContentParser.Token token;
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            // Each field in the object represents a SharedWithActionGroup
            if (token == XContentParser.Token.FIELD_NAME) {
                String fieldName = parser.currentName();

                if ("general_access".equals(fieldName)) {
                    parser.nextToken();
                    generalAccess = parser.textOrNull();
                    continue;
                }

                // Validate access level if validator is provided
                if (accessLevelValidator != null) {
                    accessLevelValidator.validate("access_level", fieldName);
                }

                parser.nextToken();

                Recipients recipients = Recipients.fromXContent(
                    parser,
                    RequestContentValidator.ARRAY_SIZE_VALIDATOR,
                    RequestContentValidator.principalValidator(false)
                );
                sharingInfo.put(fieldName, recipients);
            }
        }

        return new ShareWith(sharingInfo, generalAccess);
    }

    @Override
    public String getWriteableName() {
        return "share_with";
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeMap(sharingInfo, StreamOutput::writeString, (o, sw) -> sw.writeTo(o));
        out.writeOptionalString(generalAccess);
    }

    @Override
    public String toString() {
        return "ShareWith " + sharingInfo;
    }

    /**
     * Returns a new ShareWith by merging this and another ShareWith (adding recipients).
     */
    public ShareWith add(ShareWith other) {
        if (other == null) {
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
        // generalAccess in the patch overwrites the current value
        String newGeneralAccess = other.generalAccess != null ? other.generalAccess : this.generalAccess;
        return new ShareWith(this.sharingInfo, newGeneralAccess);
    }

    /**
     * Returns a new ShareWith by revoking recipients based on another ShareWith.
     */
    public ShareWith revoke(ShareWith other) {
        if (other == null || sharingInfo.isEmpty()) {
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
        // clear generalAccess if the revoke patch specifies the same level
        String newGeneralAccess = other.generalAccess != null && other.generalAccess.equals(this.generalAccess) ? null : this.generalAccess;
        return new ShareWith(this.sharingInfo, newGeneralAccess);
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
        return new ShareWith(cleaned, generalAccess);
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
