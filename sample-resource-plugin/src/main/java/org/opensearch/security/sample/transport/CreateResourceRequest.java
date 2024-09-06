/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.sample.transport;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.sample.Resource;

/**
 * Request object for CreateSampleResource transport action
 */
public class CreateResourceRequest<T extends Resource> extends ActionRequest {

    private final T resource;

    /**
     * Default constructor
     */
    public CreateResourceRequest(T resource) {
        this.resource = resource;
    }

    public CreateResourceRequest(StreamInput in, Reader<T> resourceReader) throws IOException {
        this.resource = resourceReader.read(in);
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
