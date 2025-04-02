/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest.revoke;

import java.io.IOException;
import java.util.List;
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
import org.opensearch.security.spi.resources.sharing.SharedWithActionGroup;

/**
 * This class represents a request to revoke access to a resource for given entities.
 *
 * @opensearch.experimental
 */
public class RevokeResourceAccessRequest extends ActionRequest {

    private final String resourceId;
    private final String resourceIndex;
    private final SharedWithActionGroup.ActionGroupRecipients revokedEntities;
    private final Set<String> actionGroups;

    /**
     * Private constructor to enforce usage of Builder
     */
    private RevokeResourceAccessRequest(Builder builder) {
        this.resourceId = builder.resourceId;
        this.resourceIndex = builder.resourceIndex;
        this.revokedEntities = builder.revokedEntities;
        this.actionGroups = builder.actionGroups;
    }

    /**
     * Static factory method to initialize RevokeResourceAccessRequest from a Map.
     */
    @SuppressWarnings("unchecked")
    public static RevokeResourceAccessRequest from(Map<String, Object> source, Map<String, String> params) throws IOException {
        Builder builder = new Builder();

        builder.resourceId((String) source.get("resource_id"));
        String resourceIndex = params.getOrDefault("resource_index", (String) source.get("resource_index"));
        if (StringUtils.isEmpty(resourceIndex)) {
            throw new IllegalArgumentException("Missing required field: resource_index");
        }
        builder.resourceIndex(resourceIndex);

        if (source.containsKey("entities_to_revoke")) {
            builder.revokedEntities((Map<String, Object>) source.get("entities_to_revoke"));
        }

        if (source.containsKey("action_groups")) {
            builder.actionGroups(Set.copyOf((List<String>) source.get("action_groups")));
        }

        return builder.build();
    }

    public RevokeResourceAccessRequest(StreamInput in) throws IOException {
        super(in);
        this.resourceId = in.readOptionalString();
        this.resourceIndex = in.readOptionalString();
        this.revokedEntities = in.readNamedWriteable(SharedWithActionGroup.ActionGroupRecipients.class);
        this.actionGroups = in.readSet(StreamInput::readString);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(resourceId);
        out.writeOptionalString(resourceIndex);
        out.writeNamedWriteable(revokedEntities);
        out.writeStringCollection(actionGroups);
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

    public SharedWithActionGroup.ActionGroupRecipients getRevokedEntities() {
        return revokedEntities;
    }

    public Set<String> getActionGroups() {
        return actionGroups;
    }

    /**
     * Builder for RevokeResourceAccessRequest
     */
    public static class Builder {
        private String resourceId;
        private String resourceIndex;
        private SharedWithActionGroup.ActionGroupRecipients revokedEntities;
        private Set<String> actionGroups;

        public Builder resourceId(String resourceId) {
            this.resourceId = resourceId;
            return this;
        }

        public Builder resourceIndex(String resourceIndex) {
            this.resourceIndex = resourceIndex;
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

        public Builder revokedEntities(SharedWithActionGroup.ActionGroupRecipients entities) {
            try {
                this.revokedEntities = entities;
            } catch (Exception e) {
                this.revokedEntities = null;
            }
            return this;
        }

        public Builder actionGroups(Set<String> actionGroups) {
            this.actionGroups = actionGroups;
            return this;
        }

        public RevokeResourceAccessRequest build() {
            // TODO Remove following line once ResourceAuthz framework is implemented as a standalone framework
            this.actionGroups = Set.of(ResourceAccessActionGroups.PLACE_HOLDER);

            return new RevokeResourceAccessRequest(this);
        }

        private SharedWithActionGroup.ActionGroupRecipients parseRevokedEntities(Map<String, Object> source) throws IOException {
            if (source == null || source.isEmpty()) {
                throw new IllegalArgumentException("entities_to_revoke is required and cannot be empty");
            }

            String jsonString = XContentFactory.jsonBuilder().map(source).toString();

            try (
                XContentParser parser = XContentType.JSON.xContent()
                    .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, jsonString)
            ) {

                return SharedWithActionGroup.ActionGroupRecipients.fromXContent(parser);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid share_with structure: " + e.getMessage(), e);
            }
        }
    }
}
