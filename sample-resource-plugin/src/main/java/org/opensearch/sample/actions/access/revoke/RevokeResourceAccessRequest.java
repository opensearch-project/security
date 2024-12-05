/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.access.revoke;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.opensearch.accesscontrol.resources.EntityType;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

public class RevokeResourceAccessRequest extends ActionRequest {

    private final String resourceId;
    private final Map<EntityType, List<String>> revokeAccess;
    private final List<String> scopes;

    public RevokeResourceAccessRequest(String resourceId, Map<EntityType, List<String>> revokeAccess, List<String> scopes) {
        this.resourceId = resourceId;
        this.revokeAccess = revokeAccess;
        this.scopes = scopes;
    }

    public RevokeResourceAccessRequest(StreamInput in) throws IOException {
        this.resourceId = in.readString();
        this.revokeAccess = in.readMap(input -> EntityType.valueOf(input.readString()), StreamInput::readStringList);
        this.scopes = in.readStringList();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(resourceId);
        out.writeMap(
            revokeAccess,
            (streamOutput, entityType) -> streamOutput.writeString(entityType.name()),
            StreamOutput::writeStringCollection
        );
        out.writeStringCollection(scopes);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getResourceId() {
        return resourceId;
    }

    public Map<EntityType, List<String>> getRevokeAccess() {
        return revokeAccess;
    }

    public List<String> getScopes() {
        return scopes;
    }
}
