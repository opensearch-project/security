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
import org.opensearch.sample.SampleResource;

/**
 * Request object for CreateSampleResource transport action
 */
public class CreateResourceRequest extends ActionRequest {

    private final SampleResource resource;

    /**
     * Default constructor
     */
    public CreateResourceRequest(SampleResource resource) {
        this.resource = resource;
    }

    public CreateResourceRequest(StreamInput in) throws IOException {
        this.resource = in.readNamedWriteable(SampleResource.class);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        resource.writeTo(out);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public SampleResource getResource() {
        return this.resource;
    }
}
