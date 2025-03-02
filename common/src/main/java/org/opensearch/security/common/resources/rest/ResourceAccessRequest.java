/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.common.resources.rest;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.common.resources.RecipientType;
import org.opensearch.security.common.resources.RecipientTypeRegistry;
import org.opensearch.security.common.resources.ShareWith;

// TODO: Fix revoked entries
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
    private ShareWith shareWith;
    private Map<RecipientType, Set<String>> revokedEntities;
    private Set<String> scopes;

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
        this.resourceIndex = params.containsKey("resource_index") ? params.get("resource_index") : (String) (source.get("resource_index"));
        this.scope = (String) source.get("scope");

        if (source.containsKey("share_with")) {
            this.shareWith = parseShareWith(source);
        }

        if (source.containsKey("revoked_entities")) {
            this.revokedEntities = parseRevokedEntities(source);
        }

        if (source.containsKey("scopes")) {
            this.scopes = Set.copyOf((Set<String>) source.get("scopes"));
        }
    }

    public ResourceAccessRequest(StreamInput in) throws IOException {
        super(in);
        this.operation = in.readEnum(Operation.class);
        this.resourceId = in.readOptionalString();
        this.resourceIndex = in.readOptionalString();
        this.scope = in.readOptionalString();
        this.shareWith = in.readOptionalWriteable(ShareWith::new);
        // this.revokedEntities = in.readMap(StreamInput::readEnum, StreamInput::readSet);
        this.scopes = in.readSet(StreamInput::readString);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(operation);
        out.writeOptionalString(resourceId);
        out.writeOptionalString(resourceIndex);
        out.writeOptionalString(scope);
        out.writeOptionalWriteable(shareWith);
        // out.writeMap(revokedEntities, StreamOutput::writeEnum, StreamOutput::writeStringCollection);
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

    /**
     * Helper method to parse revoked entities from a generic Map
     */
    @SuppressWarnings("unchecked")
    private Map<RecipientType, Set<String>> parseRevokedEntities(Map<String, Object> source) {
        Map<String, Set<String>> revokeSource = (Map<String, Set<String>>) source.get("entities");
        return revokeSource.entrySet()
            .stream()
            .collect(Collectors.toMap(entry -> RecipientTypeRegistry.fromValue(entry.getKey()), Map.Entry::getValue));
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

    public Map<RecipientType, Set<String>> getRevokedEntities() {
        return revokedEntities;
    }

    public Set<String> getScopes() {
        return scopes;
    }

}
