/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.rest.resources.access.revoke;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.resources.RecipientType;

public class RevokeResourceAccessRequest extends ActionRequest {

    private final String resourceId;
    private final String resourceIndex;
    private final Map<RecipientType, Set<String>> revokeAccess;
    private final Set<String> scopes;

    public RevokeResourceAccessRequest(
        String resourceId,
        String resourceIndex,
        Map<RecipientType, Set<String>> revokeAccess,
        Set<String> scopes
    ) {
        this.resourceId = resourceId;
        this.resourceIndex = resourceIndex;
        this.revokeAccess = revokeAccess;
        this.scopes = scopes;
    }

    public RevokeResourceAccessRequest(StreamInput in) throws IOException {
        this.resourceId = in.readString();
        this.resourceIndex = in.readString();
        this.revokeAccess = in.readMap(input -> new RecipientType(input.readString()), input -> input.readSet(StreamInput::readString));
        this.scopes = in.readSet(StreamInput::readString);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(resourceId);
        out.writeString(resourceIndex);
        out.writeMap(
            revokeAccess,
            (streamOutput, recipientType) -> streamOutput.writeString(recipientType.type()),
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

    public String getResourceIndex() {
        return resourceIndex;
    }

    public Map<RecipientType, Set<String>> getRevokeAccess() {
        return revokeAccess;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
