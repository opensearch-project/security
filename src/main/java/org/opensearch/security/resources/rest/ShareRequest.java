/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest;

import java.io.IOException;
import java.util.Map;

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
import org.opensearch.security.spi.resources.sharing.ShareWith;

/**
 * This class represents a request to share access to a resource.
 *
 */
public class ShareRequest extends ActionRequest {

    private final String resourceId;
    private final String resourceIndex;
    private final ShareWith shareWith;

    /**
     * Private constructor to enforce usage of Builder
     */
    private ShareRequest(Builder builder) {
        this.resourceId = builder.resourceId;
        this.resourceIndex = builder.resourceIndex;
        this.shareWith = builder.shareWith;
    }

    /**
     * Static factory method to initialize ShareRequest from a Map.
     */
    @SuppressWarnings("unchecked")
    public static ShareRequest from(Map<String, Object> source, Map<String, String> params) throws IOException {
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

    public ShareRequest(StreamInput in) throws IOException {
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
     * Builder for ShareRequest
     */
    public static class Builder {
        private String resourceId;
        private String resourceIndex;
        private ShareWith shareWith;

        public void resourceId(String resourceId) {
            this.resourceId = resourceId;
        }

        public void resourceIndex(String resourceIndex) {
            this.resourceIndex = resourceIndex;
        }

        public void shareWith(Map<String, Object> source) {
            try {
                this.shareWith = parseShareWith(source);
            } catch (Exception e) {
                this.shareWith = null;
            }
        }

        public void shareWith(ShareWith shareWith) {
            this.shareWith = shareWith;
        }

        public ShareRequest build() {
            return new ShareRequest(this);
        }


        private ShareWith parseShareWith(Map<String, Object> source) throws IOException {
            if (source == null || source.isEmpty()) {
                throw new IllegalArgumentException("share_with is required and cannot be empty");
            }

            String jsonString = XContentFactory.jsonBuilder().map(source).toString();

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