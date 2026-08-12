/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.io.IOException;
import java.util.Set;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

/**
 * Resolved access information for the current user on a single resource.
 *
 * @param resourceId resource identifier
 * @param resourceType resource type
 * @param owner whether the current user is the owner
 * @param admin whether the current user is an admin
 * @param effectiveAccessLevel best matching access level for the resource type, if any
 * @param accessLevels all matching access levels for the current user on this resource
 * @param allowedActions resolved actions granted to the current user
 * @param canShare whether the current user may update sharing for this resource
 */
public record ResolvedResourceAccess(String resourceId, String resourceType, boolean owner, boolean admin, String effectiveAccessLevel, Set<
    String> accessLevels, Set<String> allowedActions, boolean canShare) implements ToXContentObject {

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("resource_id", resourceId);
        builder.field("resource_type", resourceType);
        builder.field("is_owner", owner);
        builder.field("is_admin", admin);
        if (effectiveAccessLevel != null) {
            builder.field("effective_access_level", effectiveAccessLevel);
        }
        builder.field("access_levels", accessLevels);
        builder.field("allowed_actions", allowedActions);
        builder.field("can_share", canShare);
        builder.endObject();
        return builder;
    }
}
