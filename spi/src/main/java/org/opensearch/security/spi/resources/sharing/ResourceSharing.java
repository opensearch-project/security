/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources.sharing;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
    private final Logger log = LogManager.getLogger(this.getClass());

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
            Map<String, Recipients> recs = new HashMap<>();
            recs.put(accessLevel, target);
            shareWith = new ShareWith(recs);
            return;
        }
        Recipients sharedWith = shareWith.atAccessLevel(accessLevel);
        // sharedWith will be null when sharing at a new access-level
        if (sharedWith == null) {
            // update the ShareWith object
            shareWith = shareWith.updateSharingInfo(accessLevel, target);
        } else {
            sharedWith.share(target);
        }
    }

    public void revoke(String accessLevel, Recipients target) {
        if (shareWith == null) {
            log.warn("Cannot revoke access as resource {} is not shared with anyone", this.resourceId);
            return;
        }

        Recipients sharedWith = shareWith.atAccessLevel(accessLevel);
        // sharedWith will only be null if given access level doesn't exist in which case we log a warning message
        if (sharedWith == null) {
            log.warn(
                "Cannot revoke access to {} for {} as the resource is not shared at accessLevel {}",
                this.resourceId,
                accessLevel,
                target
            );
        } else {
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
        return "ResourceSharing {" + "resourceId='" + resourceId + '\'' + ", createdBy=" + createdBy + ", sharedWith=" + shareWith + '}';
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

    /**
     * Fetches all access-levels where at-least 1 recipient matches the given set of targets
     * @param recipientType the type of recipient to be matched against
     * @param entities targets to look for
     * @return set of access-levels which contain given nay of the targets
     */
    public Set<String> fetchAccessLevels(Recipient recipientType, Set<String> entities) {
        if (shareWith == null) {
            return Collections.emptySet();
        }
        Set<String> matchingGroups = new HashSet<>();
        for (Map.Entry<String, Recipients> entry : shareWith.getSharingInfo().entrySet()) {
            String accessLevel = entry.getKey();
            Recipients recipients = entry.getValue();

            Set<String> sharingRecipients = new HashSet<>(recipients.getRecipients().getOrDefault(recipientType, Set.of()));

            // if there’s a wildcard (i.e. the document is shared publicly at this access-level), or at least one entity in common, add the
            // level to a final list of groups
            boolean matchesWildcard = sharingRecipients.contains("*");
            boolean intersects = !Collections.disjoint(sharingRecipients, entities);

            if (matchesWildcard || intersects) {
                matchingGroups.add(accessLevel);
            }
        }
        return matchingGroups;
    }

    /**
     * Returns all principals (users, roles, backend_roles) that have access to this resource,
     * including the creator and all shared recipients, formatted with appropriate prefixes.
     *
     * @return List of principals in format ["user:username", "role:rolename", "backend:backend_role"]
     */
    public List<String> getAllPrincipals() {
        List<String> principals = new ArrayList<>();

        // Add creator
        if (createdBy != null) {
            principals.add("user:" + createdBy.getUsername());
        }

        // Add shared recipients
        if (shareWith != null) {
            // shared with at any access level
            for (Recipients recipients : shareWith.getSharingInfo().values()) {
                Map<Recipient, Set<String>> recipientMap = recipients.getRecipients();

                // Add users
                Set<String> users = recipientMap.getOrDefault(Recipient.USERS, Collections.emptySet());
                for (String user : users) {
                    principals.add("user:" + user);
                }

                // Add roles
                Set<String> roles = recipientMap.getOrDefault(Recipient.ROLES, Collections.emptySet());
                for (String role : roles) {
                    principals.add("role:" + role);
                }

                // Add backend roles
                Set<String> backendRoles = recipientMap.getOrDefault(Recipient.BACKEND_ROLES, Collections.emptySet());
                for (String backendRole : backendRoles) {
                    principals.add("backend:" + backendRole);
                }
            }
        }

        return principals;
    }
}
