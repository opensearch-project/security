/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest.share;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.spi.resources.ResourceAccessActionGroups;
import org.opensearch.security.spi.resources.sharing.ShareWith;
import org.opensearch.security.spi.resources.sharing.SharedWithActionGroup;

/**
 * This class represents a request to share access to a resource.
 *
 * @opensearch.experimental
 */
public class ShareResourceRequest extends ActionRequest {

    private final String resourceId;
    private final String resourceIndex;
    private final ShareWith shareWith;

    /**
     * Private constructor to enforce usage of Builder
     */
    private ShareResourceRequest(Builder builder) {
        this.resourceId = builder.resourceId;
        this.resourceIndex = builder.resourceIndex;
        this.shareWith = builder.shareWith;
    }

    /**
     * Static factory method to initialize ShareResourceRequest from a Map.
     */
    @SuppressWarnings("unchecked")
    public static ShareResourceRequest from(Map<String, Object> source, Map<String, String> params) throws IOException {
        Builder builder = new Builder();

        builder.resourceId((String) source.get("resource_id"));
        String resourceIndex = params.getOrDefault("resource_index", (String) source.get("resource_index"));
        if (StringUtils.isEmpty(resourceIndex)) {
            throw new IllegalArgumentException("Missing required field: resource_index");
        }
        builder.resourceIndex(resourceIndex);

        if (source.containsKey("share_with")) {
            builder.shareWith((Map<String, Object>) source.get("share_with"));
        }

        return builder.build();
    }

    public ShareResourceRequest(StreamInput in) throws IOException {
        super(in);
        this.resourceId = in.readOptionalString();
        this.resourceIndex = in.readOptionalString();
        this.shareWith = in.readOptionalWriteable(ShareWith::new);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(resourceId);
        out.writeOptionalString(resourceIndex);
        out.writeOptionalWriteable(shareWith);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getResourceId() {
        return resourceId;
    }

    public String getResourceIndex() {
        return resourceIndex;
    }

    public ShareWith getShareWith() {
        return shareWith;
    }

    /**
     * Builder for ShareResourceRequest
     */
    public static class Builder {
        private String resourceId;
        private String resourceIndex;
        private ShareWith shareWith;

        public Builder resourceId(String resourceId) {
            this.resourceId = resourceId;
            return this;
        }

        public Builder resourceIndex(String resourceIndex) {
            this.resourceIndex = resourceIndex;
            return this;
        }

        public Builder shareWith(Map<String, Object> source) {
            try {
                this.shareWith = parseShareWith(source);
            } catch (Exception e) {
                this.shareWith = null;
            }
            return this;
        }

        public Builder shareWith(SharedWithActionGroup.ActionGroupRecipients recipients) {
            try {
                this.shareWith = parseShareWith(recipients);
            } catch (Exception e) {
                this.shareWith = null;
            }
            return this;
        }

        public ShareResourceRequest build() {
            return new ShareResourceRequest(this);
        }

        private ShareWith parseShareWith(SharedWithActionGroup.ActionGroupRecipients recipients) {
            SharedWithActionGroup s = new SharedWithActionGroup(ResourceAccessActionGroups.PLACE_HOLDER, recipients);
            return new ShareWith(Set.of(s));
        }

        private ShareWith parseShareWith(Map<String, Object> source) throws IOException {
            if (source == null || source.isEmpty()) {
                throw new IllegalArgumentException("share_with is required and cannot be empty");
            }

            // TODO Remove lines 212-219 once ResourceAuthz framework is implemented as a standalone framework
            // Input Structure for share_with:
            // { users: [...], roles: [...], backend_roles: [...] }
            // Final Structure:
            // { "<ResourceAccessActionGroups.PLACE_HOLDER>" : { users: [...], roles: [...], backend_roles: [...] } }
            // We add ResourceAccessActionGroups.PLACE_HOLDER as an action-group to allow share_with to be future expandable to allow
            // sharing with different action groups
            Map<String, Object> shareWithMap = new HashMap<>();
            shareWithMap.put(ResourceAccessActionGroups.PLACE_HOLDER, source);

            String jsonString = XContentFactory.jsonBuilder().map(shareWithMap).toString();

            try (
                XContentParser parser = XContentType.JSON.xContent()
                    .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, jsonString)
            ) {

                return ShareWith.fromXContent(parser);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid share_with structure: " + e.getMessage(), e);
            }
        }
    }
}
