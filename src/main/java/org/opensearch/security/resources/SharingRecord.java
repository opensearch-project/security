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
