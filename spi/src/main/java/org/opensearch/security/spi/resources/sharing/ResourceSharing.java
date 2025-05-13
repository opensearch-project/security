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
     * The unique identifier of the resource sharing entry
     *
     * TODO If this moves to a shadow index for each resource index, then use the resourceId as the key for both
     */
    private String docId;

    /**
     * The index where the resource is defined
     */
    private String sourceIdx;

    /**
     * The unique identifier of the resource
     */
    private String resourceId;

    /**
     * Information about who created the resource
     */
    private CreatedBy createdBy;

    /**
     * Information about with whom the resource is shared with
     */
    private ShareWith shareWith;

    public ResourceSharing(String sourceIdx, String resourceId, CreatedBy createdBy, ShareWith shareWith) {
        this.sourceIdx = sourceIdx;
        this.resourceId = resourceId;
        this.createdBy = createdBy;
        this.shareWith = shareWith;
    }

    public String getDocId() {
        return docId;
    }

    public void setDocId(String docId) {
        this.docId = docId;
    }

    public String getSourceIdx() {
        return sourceIdx;
    }

    public void setSourceIdx(String sourceIdx) {
        this.sourceIdx = sourceIdx;
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

    public void setCreatedBy(CreatedBy createdBy) {
        this.createdBy = createdBy;
    }

    public ShareWith getShareWith() {
        return shareWith;
    }

    public void setShareWith(ShareWith shareWith) {
        this.shareWith = shareWith;
    }

    public void share(String accessLevel, SharedWithActionGroup target) {
        if (shareWith == null) {
            shareWith = new ShareWith(Set.of(target));
        } else {
            SharedWithActionGroup sharedWith = shareWith.atAccessLevel(accessLevel);
            sharedWith.share(target);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ResourceSharing resourceSharing = (ResourceSharing) o;
        return Objects.equals(getSourceIdx(), resourceSharing.getSourceIdx())
            && Objects.equals(getResourceId(), resourceSharing.getResourceId())
            && Objects.equals(getCreatedBy(), resourceSharing.getCreatedBy())
            && Objects.equals(getShareWith(), resourceSharing.getShareWith());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getSourceIdx(), getResourceId(), getCreatedBy(), getShareWith());
    }

    @Override
    public String toString() {
        return "ResourceSharing {"
            + "sourceIdx='"
            + sourceIdx
            + '\''
            + ", resourceId='"
            + resourceId
            + '\''
            + ", createdBy="
            + createdBy
            + ", sharedWith="
            + shareWith
            + '}';
    }

    @Override
    public String getWriteableName() {
        return "resource_sharing";
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(sourceIdx);
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
        builder.startObject().field("source_idx", sourceIdx).field("resource_id", resourceId).field("created_by");
        createdBy.toXContent(builder, params);
        if (shareWith != null && !shareWith.getSharedWithActionGroups().isEmpty()) {
            builder.field("share_with");
            shareWith.toXContent(builder, params);
        }
        return builder.endObject();
    }

    public static ResourceSharing fromXContent(XContentParser parser) throws IOException {
        String sourceIdx = null;
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
                    case "source_idx":
                        sourceIdx = parser.text();
                        break;
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

        validateRequiredField("source_idx", sourceIdx);
        validateRequiredField("resource_id", resourceId);
        validateRequiredField("created_by", createdBy);

        return new ResourceSharing(sourceIdx, resourceId, createdBy, shareWith);
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
        return this.createdBy != null && this.createdBy.getCreator().equals(userName);
    }

    /**
     * Checks if the given resource is shared with everyone, i.e. the entity list is "*"
     *
     * @return True if the resource is shared with everyone, false otherwise.
     */
    public boolean isSharedWithEveryone() {
        return this.shareWith != null
            && this.shareWith.getSharedWithActionGroups()
                .stream()
                .anyMatch(sharedWithActionGroup -> sharedWithActionGroup.getActionGroup().equals("*"));
    }

    /**
     * Checks if the given resource is shared with the specified entities.
     *
     * @param recipient The recipient entity
     * @param entities  The set of entities to check for sharing.
     * @param actionGroups The set of action groups to check for sharing.
     *
     * @return True if the resource is shared with the entities, false otherwise.
     */
    public boolean isSharedWithEntity(Recipient recipient, Set<String> entities, Set<String> actionGroups) {
        if (shareWith == null) {
            return false;
        }

        return shareWith.getSharedWithActionGroups()
            .stream()
            // only keep the action-groups we care about
            .filter(sWAG -> actionGroups.contains(sWAG.getActionGroup()))
            // for each matching action-group, grab the recipients’ entities for YOUR recipient
            .map(sWAG -> sWAG.getSharedWithPerActionGroup().getRecipients().getOrDefault(recipient, Set.of()))
            // check intersection with input entities
            .anyMatch(sharedEntities -> {
                Set<String> intersection = new HashSet<>(sharedEntities);
                intersection.retainAll(entities);
                return !intersection.isEmpty();
            });
    }
}
