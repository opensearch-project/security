/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.access.revoke;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

import org.opensearch.accesscontrol.resources.EntityType;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.sample.utils.Validation;

public class RevokeResourceAccessRequest extends ActionRequest {

    private final String resourceId;
    private final Map<EntityType, Set<String>> revokeAccess;
    private final Set<String> scopes;

    public RevokeResourceAccessRequest(String resourceId, Map<EntityType, Set<String>> revokeAccess, Set<String> scopes) {
        this.resourceId = resourceId;
        this.revokeAccess = revokeAccess;
        this.scopes = scopes;
    }

    public RevokeResourceAccessRequest(StreamInput in) throws IOException {
        this.resourceId = in.readString();
        this.revokeAccess = in.readMap(input -> EntityType.valueOf(input.readString()), input -> input.readSet(StreamInput::readString));
        this.scopes = in.readSet(StreamInput::readString);
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

        if (!(this.scopes == null)) {
            return Validation.validateScopes(this.scopes);
        }

        return null;
    }

    public String getResourceId() {
        return resourceId;
    }

    public Map<EntityType, Set<String>> getRevokeAccess() {
        return revokeAccess;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
