/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.common.resources.rest;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.common.resources.ShareWith;

public class ResourceAccessRequest extends ActionRequest {

    public enum Operation {
        LIST,
        SHARE,
        REVOKE,
        VERIFY
    }

    private final Operation operation;
    private final String resourceId;
    private final String resourceIndex;
    private final String scope;
    private final ShareWith shareWith;
    private final Map<String, Set<String>> revokedEntities;
    private final Set<String> scopes;

    /**
     * Private constructor to enforce usage of Builder
     */
    private ResourceAccessRequest(Builder builder) {
        this.operation = builder.operation;
        this.resourceId = builder.resourceId;
        this.resourceIndex = builder.resourceIndex;
        this.scope = builder.scope;
        this.shareWith = builder.shareWith;
        this.revokedEntities = builder.revokedEntities;
        this.scopes = builder.scopes;
    }

    /**
     * New Constructor: Initialize request from a `Map<String, Object>`
     */
    @SuppressWarnings("unchecked")
    public ResourceAccessRequest(Map<String, Object> source, Map<String, String> params) throws IOException {
        if (source.containsKey("operation")) {
            this.operation = (Operation) source.get("operation");
        } else {
            throw new IllegalArgumentException("Missing required field: operation");
        }

        this.resourceId = (String) source.get("resource_id");
        this.resourceIndex = params.containsKey("resource_index") ? params.get("resource_index") : (String) source.get("resource_index");
        this.scope = (String) source.get("scope");

        if (source.containsKey("share_with")) {
            this.shareWith = parseShareWith(source);
        } else {
            this.shareWith = null;
        }

        if (source.containsKey("entities_to_revoke")) {
            this.revokedEntities = ((Map<String, Set<String>>) source.get("entities_to_revoke"));
        } else {
            this.revokedEntities = null;
        }

        if (source.containsKey("scopes")) {
            this.scopes = Set.copyOf((List<String>) source.get("scopes"));
        } else {
            this.scopes = null;
        }
    }

    public ResourceAccessRequest(StreamInput in) throws IOException {
        super(in);
        this.operation = in.readEnum(Operation.class);
        this.resourceId = in.readOptionalString();
        this.resourceIndex = in.readOptionalString();
        this.scope = in.readOptionalString();
        this.shareWith = in.readOptionalWriteable(ShareWith::new);
        this.revokedEntities = in.readMap(StreamInput::readString, valIn -> valIn.readSet(StreamInput::readString));
        this.scopes = in.readSet(StreamInput::readString);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(operation);
        out.writeOptionalString(resourceId);
        out.writeOptionalString(resourceIndex);
        out.writeOptionalString(scope);
        out.writeOptionalWriteable(shareWith);
        out.writeMap(revokedEntities, StreamOutput::writeString, StreamOutput::writeStringCollection);
        out.writeStringCollection(scopes);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    /**
     * Parse the share with structure from the request body.
     *
     * @param source the request body
     * @return the parsed ShareWith object
     * @throws IOException if an I/O error occurs
     */
    @SuppressWarnings("unchecked")
    private ShareWith parseShareWith(Map<String, Object> source) throws IOException {
        Map<String, Object> shareWithMap = (Map<String, Object>) source.get("share_with");
        if (shareWithMap == null || shareWithMap.isEmpty()) {
            throw new IllegalArgumentException("share_with is required and cannot be empty");
        }

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

    public Operation getOperation() {
        return operation;
    }

    public String getResourceId() {
        return resourceId;
    }

    public String getResourceIndex() {
        return resourceIndex;
    }

    public String getScope() {
        return scope;
    }

    public ShareWith getShareWith() {
        return shareWith;
    }

    public Map<String, Set<String>> getRevokedEntities() {
        return revokedEntities;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    /**
     * Builder for ResourceAccessRequest
     */
    public static class Builder {
        private Operation operation;
        private String resourceId;
        private String resourceIndex;
        private String scope;
        private ShareWith shareWith;
        private Map<String, Set<String>> revokedEntities;
        private Set<String> scopes;

        public Builder setOperation(Operation operation) {
            this.operation = operation;
            return this;
        }

        public Builder setResourceId(String resourceId) {
            this.resourceId = resourceId;
            return this;
        }

        public Builder setResourceIndex(String resourceIndex) {
            this.resourceIndex = resourceIndex;
            return this;
        }

        public Builder setScope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder setShareWith(ShareWith shareWith) {
            this.shareWith = shareWith;
            return this;
        }

        public Builder setRevokedEntities(Map<String, Set<String>> revokedEntities) {
            this.revokedEntities = revokedEntities;
            return this;
        }

        public Builder setScopes(Set<String> scopes) {
            this.scopes = scopes;
            return this;
        }

        public ResourceAccessRequest build() {
            return new ResourceAccessRequest(this);
        }
    }
}
