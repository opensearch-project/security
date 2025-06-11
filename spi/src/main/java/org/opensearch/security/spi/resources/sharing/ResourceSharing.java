/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources.sharing;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentFragment;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

/**
 * Represents a resource sharing configuration that manages access control for OpenSearch resources.
 * This class holds information about shared resources including their source, creator, and sharing permissions.
 * The class maintains information about:
 * <ul>
 *   <li>The source index where the resource is defined</li>
 *   <li>The unique identifier of the resource</li>
 *   <li>The creator's information</li>
 *   <li>The sharing permissions and recipients</li>
 * </ul>
 *
 * @opensearch.experimental
 * @see org.opensearch.security.spi.resources.sharing.CreatedBy
 * @see org.opensearch.security.spi.resources.sharing.ShareWith
 */
public class ResourceSharing implements ToXContentFragment, NamedWriteable {

    /**
     * The unique identifier of the resource and the resource sharing entry
     */
    private String resourceId;

    /**
     * Information about who created the resource
     */
    private final CreatedBy createdBy;

    /**
     * Information about with whom the resource is shared with
     */
    private ShareWith shareWith;

    public ResourceSharing(String resourceId, CreatedBy createdBy, ShareWith shareWith) {
        this.resourceId = resourceId;
        this.createdBy = createdBy;
        this.shareWith = shareWith;
    }

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public CreatedBy getCreatedBy() {
        return createdBy;
    }

    public ShareWith getShareWith() {
        return shareWith;
    }

    public void share(String accessLevel, Recipients target) {
        if (shareWith == null) {
            shareWith = new ShareWith(Map.of(accessLevel, target));
        } else {
            Recipients sharedWith = shareWith.atAccessLevel(accessLevel);
            sharedWith.share(target);
        }
    }

    public void revoke(String accessLevel, Recipients target) {
        if (shareWith == null) {
            // TODO log a warning that this is a noop
            return;
        } else {
            Recipients sharedWith = shareWith.atAccessLevel(accessLevel);
            sharedWith.revoke(target);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ResourceSharing resourceSharing = (ResourceSharing) o;
        return Objects.equals(getResourceId(), resourceSharing.getResourceId())
            && Objects.equals(getCreatedBy(), resourceSharing.getCreatedBy())
            && Objects.equals(getShareWith(), resourceSharing.getShareWith());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getResourceId(), getCreatedBy(), getShareWith());
    }

    @Override
    public String toString() {
        return "ResourceSharing {" + ", resourceId='" + resourceId + '\'' + ", createdBy=" + createdBy + ", sharedWith=" + shareWith + '}';
    }

    @Override
    public String getWriteableName() {
        return "resource_sharing";
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(resourceId);
        createdBy.writeTo(out);
        if (shareWith != null) {
            out.writeBoolean(true);
            shareWith.writeTo(out);
        } else {
            out.writeBoolean(false);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject().field("resource_id", resourceId).field("created_by");
        createdBy.toXContent(builder, params);
        if (shareWith != null) {
            builder.field("share_with");
            shareWith.toXContent(builder, params);
        }
        return builder.endObject();
    }

    public static ResourceSharing fromXContent(XContentParser parser) throws IOException {
        String resourceId = null;
        CreatedBy createdBy = null;
        ShareWith shareWith = null;

        String currentFieldName = null;
        XContentParser.Token token;

        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else {
                switch (Objects.requireNonNull(currentFieldName)) {
                    case "resource_id":
                        resourceId = parser.text();
                        break;
                    case "created_by":
                        createdBy = CreatedBy.fromXContent(parser);
                        break;
                    case "share_with":
                        shareWith = ShareWith.fromXContent(parser);
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
        }

        validateRequiredField("resource_id", resourceId);
        validateRequiredField("created_by", createdBy);

        return new ResourceSharing(resourceId, createdBy, shareWith);
    }

    private static <T> void validateRequiredField(String field, T value) {
        if (value == null) {
            throw new IllegalArgumentException(field + " is required");
        }
    }

    /**
     * Checks if the given resource is owned by the specified user.
     *
     * @param userName The username to check ownership against.
     * @return True if the resource is owned by the user, false otherwise.
     */
    public boolean isCreatedBy(String userName) {
        return this.createdBy != null && this.createdBy.getUsername().equals(userName);
    }

    /**
     * Checks if the given resource is shared with everyone, i.e. the entity list is "*"
     *
     * @return True if the resource is shared with everyone, false otherwise.
     */
    public boolean isSharedWithEveryone() {
        return this.shareWith != null && this.shareWith.isPublic();
    }

    /**
     * Checks if the given resource is shared with the specified entities.
     *
     * @param recipientType The recipient type
     * @param targets  The set of targets to check for sharing.
     * @param accessLevel The access level to check for sharing.
     *
     * @return True if the resource is shared with the entities, false otherwise.
     */
    public boolean isSharedWithEntity(Recipient recipientType, Set<String> targets, String accessLevel) {
        if (shareWith == null || shareWith.atAccessLevel(accessLevel) == null) {
            return false;
        }

        return shareWith.atAccessLevel(accessLevel).isSharedWithAny(recipientType, targets);
    }
}
