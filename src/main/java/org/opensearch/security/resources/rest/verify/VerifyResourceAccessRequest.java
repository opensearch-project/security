/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest.verify;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.spi.resources.ResourceAccessActionGroups;

/**
 * This class represents a request to verify access to a resource.
 *
 * @opensearch.experimental
 */
public class VerifyResourceAccessRequest extends ActionRequest {

    private final String resourceId;
    private final String resourceIndex;
    private final Set<String> actionGroups;

    /**
     * Private constructor to enforce usage of Builder
     */
    private VerifyResourceAccessRequest(Builder builder) {
        this.resourceId = builder.resourceId;
        this.resourceIndex = builder.resourceIndex;
        this.actionGroups = builder.actionGroups;
    }

    /**
     * Static factory method to initialize VerifyResourceAccessRequest from a Map.
     */
    @SuppressWarnings("unchecked")
    public static VerifyResourceAccessRequest from(Map<String, Object> source, Map<String, String> params) throws IOException {
        Builder builder = new Builder();

        builder.resourceId((String) source.get("resource_id"));
        String resourceIndex = params.getOrDefault("resource_index", (String) source.get("resource_index"));
        if (StringUtils.isEmpty(resourceIndex)) {
            throw new IllegalArgumentException("Missing required field: resource_index");
        }
        builder.resourceIndex(resourceIndex);

        if (source.containsKey("action_groups")) {
            builder.actionGroups(Set.copyOf((List<String>) source.get("action_groups")));
        }

        return builder.build();
    }

    public VerifyResourceAccessRequest(StreamInput in) throws IOException {
        super(in);
        this.resourceId = in.readOptionalString();
        this.resourceIndex = in.readOptionalString();
        this.actionGroups = in.readSet(StreamInput::readString);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(resourceId);
        out.writeOptionalString(resourceIndex);
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

    public Set<String> getActionGroups() {
        return actionGroups;
    }

    /**
     * Builder for VerifyResourceAccessRequest
     */
    public static class Builder {
        private String resourceId;
        private String resourceIndex;
        private Set<String> actionGroups;

        public Builder resourceId(String resourceId) {
            this.resourceId = resourceId;
            return this;
        }

        public Builder resourceIndex(String resourceIndex) {
            this.resourceIndex = resourceIndex;
            return this;
        }

        public Builder actionGroups(Set<String> actionGroups) {
            this.actionGroups = actionGroups;
            return this;
        }

        public VerifyResourceAccessRequest build() {
            // TODO Remove following line once ResourceAuthz framework is implemented as a standalone framework
            this.actionGroups = Set.of(ResourceAccessActionGroups.PLACE_HOLDER);

            return new VerifyResourceAccessRequest(this);
        }
    }
}
