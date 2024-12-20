/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.resource.create;

import java.io.IOException;

import org.opensearch.accesscontrol.resources.Resource;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

/**
 * Request object for CreateSampleResource transport action
 */
public class CreateResourceRequest extends ActionRequest {

    private final Resource resource;

    /**
     * Default constructor
     */
    public CreateResourceRequest(Resource resource) {
        this.resource = resource;
    }

    public CreateResourceRequest(StreamInput in) throws IOException {
        this.resource = in.readNamedWriteable(Resource.class);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        resource.writeTo(out);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public Resource getResource() {
        return this.resource;
    }
}
