/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.api.share;

import java.io.IOException;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.spi.resources.sharing.ShareWith;

import joptsimple.internal.Strings;

/**
 * This class represents a request to share access to a resource.
 *
 */
public class ShareRequest extends ActionRequest {

    @JsonProperty("resource_id")
    private final String resourceId;
    @JsonProperty("resource_index")
    private final String resourceIndex;
    @JsonProperty("share_with")
    private final ShareWith shareWith;
    @JsonProperty("patch")
    private final JsonNode patch;

    /**
     * Private constructor to enforce usage of Builder
     */
    private ShareRequest(Builder builder) {
        this.resourceId = builder.resourceId;
        this.resourceIndex = builder.resourceIndex;
        this.shareWith = builder.shareWith;
        this.patch = builder.patch;
    }

    /**
     * Static factory method to initialize ShareRequest from a Map.
     */
    @SuppressWarnings("unchecked")
    public static ShareRequest from(Map<String, Object> source) throws IOException {
        Builder builder = new Builder();

        builder.resourceId((String) source.get("resource_id"));

        builder.resourceIndex((String) source.get("resource_index"));

        if (source.containsKey("share_with")) {
            builder.shareWith((Map<String, Object>) source.get("share_with"));
        }

        if (source.containsKey("patch")) {
            builder.patch((JsonNode) source.get("patch"));
        }

        return builder.build();
    }

    public ShareRequest(StreamInput in) throws IOException {
        super(in);
        this.resourceId = in.readString();
        this.resourceIndex = in.readString();
        this.shareWith = in.readOptionalWriteable(ShareWith::new);
        this.patch = Utils.toJsonNode(in.readString());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(resourceId);
        out.writeString(resourceIndex);
        if (shareWith != null) {
            shareWith.writeTo(out);
        }
        if (patch != null) {
            out.writeString(patch.toString());
        }
    }

    @Override
    public ActionRequestValidationException validate() {
        if (Strings.isNullOrEmpty(resourceIndex) || Strings.isNullOrEmpty(resourceId)) {
            throw new ActionRequestValidationException();
        }
        // either of shareWith or patch must be present in the request
        if (shareWith == null && (patch == null || patch.isEmpty())) {
            throw new ActionRequestValidationException();
        }
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

    public JsonNode getPatch() {
        return patch;
    }

    /**
     * Builder for ShareRequest
     */
    public static class Builder {
        private String resourceId;
        private String resourceIndex;
        private ShareWith shareWith;
        private JsonNode patch;

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

        public void patch(JsonNode patch) {
            this.patch = patch;
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
