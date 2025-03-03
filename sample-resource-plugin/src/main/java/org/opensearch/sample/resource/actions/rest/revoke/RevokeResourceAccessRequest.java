/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.revoke;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

/**
 * Request object for revoking access to a sample resource transport action
 */
public class RevokeResourceAccessRequest extends ActionRequest {

    String resourceId;
    Map<String, Object> entitiesToRevoke;
    Set<String> scopes;

    public RevokeResourceAccessRequest(String resourceId, Map<String, Object> entitiesToRevoke, List<String> scopes) {
        this.resourceId = resourceId;
        this.entitiesToRevoke = entitiesToRevoke;
        this.scopes = new HashSet<>(scopes);
    }

    public RevokeResourceAccessRequest(StreamInput in) throws IOException {
        resourceId = in.readString();
        entitiesToRevoke = in.readMap();
        scopes = in.readSet(StreamInput::readString);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(resourceId);
        out.writeMap(entitiesToRevoke);
        out.writeStringCollection(scopes);

    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getResourceId() {
        return resourceId;
    }

    public Map<String, Object> getEntitiesToRevoke() {
        return entitiesToRevoke;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
