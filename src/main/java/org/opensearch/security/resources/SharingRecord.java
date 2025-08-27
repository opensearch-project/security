/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.io.IOException;
import java.util.Objects;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.spi.resources.sharing.CreatedBy;
import org.opensearch.security.spi.resources.sharing.ShareWith;

public class SharingRecord implements ToXContentObject {
    private String resourceId;
    private CreatedBy createdBy;
    private ShareWith shareWith;
    private boolean canShare;

    public SharingRecord(String resourceId, CreatedBy createdBy, ShareWith shareWith) {
        this.resourceId = resourceId;
        this.createdBy = createdBy;
        this.shareWith = shareWith;
        this.canShare = false;
    }

    public void setCanShare(boolean canShare) {
        this.canShare = canShare;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("resourceId", resourceId);
        builder.field("createdBy", createdBy);
        builder.field("shareWith", shareWith);
        builder.field("canShare", canShare);
        builder.endObject();
        return builder;
    }

    public static SharingRecord fromXContent(XContentParser parser) throws IOException {
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

        return new SharingRecord(resourceId, createdBy, shareWith);
    }
}
