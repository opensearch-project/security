/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.io.IOException;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;

/**
 * Record class that is used as response to dashboards api {@code `/resource/list`} request
 * @param resourceSharing the sharing record document to be returned
 * @param canShare to indicate whether user can share this further
 */
public record SharingRecord(ResourceSharing resourceSharing, boolean canShare) implements ToXContentObject {

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("resource_id", resourceSharing.getResourceId());

        builder.field("created_by");
        resourceSharing.getCreatedBy().toXContent(builder, params);

        if (resourceSharing.getShareWith() != null) {
            builder.field("share_with");
            resourceSharing.getShareWith().toXContent(builder, params);
        }
        builder.field("can_share", canShare);
        builder.endObject();
        return builder;
    }
}
