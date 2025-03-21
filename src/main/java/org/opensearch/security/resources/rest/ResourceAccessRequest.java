/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

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
 * This class represents a request to access a resource.
 * It encapsulates the operation, resource ID, resource index, scope, share with information, revoked entities, and scopes.
 *
 * @opensearch.experimental
 */
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
        this.shareWith = builder.shareWith;
        this.revokedEntities = builder.revokedEntities;
        this.scopes = builder.scopes;
    }

    /**
     * Static factory method to initialize ResourceAccessRequest from a Map.
     */
    @SuppressWarnings("unchecked")
    public static ResourceAccessRequest from(Map<String, Object> source, Map<String, String> params) throws IOException {
        Builder builder = new Builder();

        if (source.containsKey("operation")) {
            builder.operation((Operation) source.get("operation"));
        } else {
            throw new IllegalArgumentException("Missing required field: operation");
        }

        builder.resourceId((String) source.get("resource_id"));
        String resourceIndex = params.getOrDefault("resource_index", (String) source.get("resource_index"));
        if (StringUtils.isEmpty(resourceIndex)) {
            throw new IllegalArgumentException("Missing required field: resource_index");
        }
        builder.resourceIndex(resourceIndex);

        if (source.containsKey("share_with")) {
            builder.shareWith((Map<String, Object>) source.get("share_with"));
        }

        if (source.containsKey("entities_to_revoke")) {
            builder.revokedEntities((Map<String, Object>) source.get("entities_to_revoke"));
        }

        if (source.containsKey("scopes")) {
            builder.scopes(Set.copyOf((List<String>) source.get("scopes"))); // Ensuring Set<String> type
        }

        return builder.build();
    }

    public ResourceAccessRequest(StreamInput in) throws IOException {
        super(in);
        this.operation = in.readEnum(Operation.class);
        this.resourceId = in.readOptionalString();
        this.resourceIndex = in.readOptionalString();
        this.shareWith = in.readOptionalWriteable(ShareWith::new);
        this.revokedEntities = in.readMap(StreamInput::readString, valIn -> valIn.readSet(StreamInput::readString));
        this.scopes = in.readSet(StreamInput::readString);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(operation);
        out.writeOptionalString(resourceId);
        out.writeOptionalString(resourceIndex);
        out.writeOptionalWriteable(shareWith);
        out.writeMap(revokedEntities, StreamOutput::writeString, StreamOutput::writeStringCollection);
        out.writeStringCollection(scopes);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
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
        private ShareWith shareWith;
        private Map<String, Set<String>> revokedEntities;
        private Set<String> scopes;

        public Builder operation(Operation operation) {
            this.operation = operation;
            return this;
        }

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

        public Builder revokedEntities(Map<String, Object> source) {
            try {
                this.revokedEntities = parseRevokedEntities(source);
            } catch (Exception e) {
                this.revokedEntities = null;
            }
            return this;
        }

        public Builder scopes(Set<String> scopes) {
            this.scopes = scopes;
            return this;
        }

        public ResourceAccessRequest build() {
            return new ResourceAccessRequest(this);
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

        private Map<String, Set<String>> parseRevokedEntities(Map<String, Object> source) {

            return source.entrySet()
                .stream()
                .filter(entry -> entry.getValue() instanceof Collection<?>)
                .collect(
                    Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> ((Collection<?>) entry.getValue()).stream()
                            .filter(String.class::isInstance)
                            .map(String.class::cast)
                            .collect(Collectors.toSet())
                    )
                );
        }
    }
}
