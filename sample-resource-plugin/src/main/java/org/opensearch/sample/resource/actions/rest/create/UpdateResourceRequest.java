/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.create;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.spi.resources.Resource;

/**
 * Request object for UpdateResource transport action
 */
public class UpdateResourceRequest extends ActionRequest {

    private final String resourceId;
    private final Resource resource;

    /**
     * Default constructor
     */
    public UpdateResourceRequest(String resourceId, Resource resource) {
        this.resourceId = resourceId;
        this.resource = resource;
    }

    public UpdateResourceRequest(StreamInput in) throws IOException {
        this.resourceId = in.readString();
        this.resource = in.readNamedWriteable(Resource.class);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(resourceId);
        resource.writeTo(out);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public Resource getResource() {
        return this.resource;
    }

    public String getResourceId() {
        return this.resourceId;
    }
}
