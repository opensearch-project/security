/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.revoke;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.DocRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.spi.resources.sharing.ShareWith;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;

/**
 * Request object for revoking access to a sample resource
 */
public class RevokeResourceAccessRequest extends ActionRequest implements DocRequest {

    String resourceId;
    ShareWith revokeAccess;

    public RevokeResourceAccessRequest(String resourceId, ShareWith entitiesToRevoke) {
        this.resourceId = resourceId;
        this.revokeAccess = entitiesToRevoke;
    }

    public RevokeResourceAccessRequest(StreamInput in) throws IOException {
        resourceId = in.readString();
        revokeAccess = new ShareWith(in);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(resourceId);
        revokeAccess.writeTo(out);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getResourceId() {
        return resourceId;
    }

    public ShareWith getEntitiesToRevoke() {
        return revokeAccess;
    }

    @Override
    public String index() {
        return RESOURCE_INDEX_NAME;
    }

    @Override
    public String id() {
        return resourceId;
    }

    @Override
    public String type() {
        return RESOURCE_TYPE;
    }
}
