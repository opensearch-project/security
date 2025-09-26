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
import org.opensearch.action.DocRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.sample.SampleResource;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;

/**
 * Request object for CreateSampleResource transport action
 */
public class CreateResourceRequest extends ActionRequest implements DocRequest {

    private final SampleResource resource;
    private final boolean shouldStoreUser;

    /**
     * Default constructor
     */
    public CreateResourceRequest(SampleResource resource, boolean shouldStoreUser) {
        this.resource = resource;
        this.shouldStoreUser = shouldStoreUser;
    }

    public CreateResourceRequest(StreamInput in) throws IOException {
        this.resource = in.readNamedWriteable(SampleResource.class);
        this.shouldStoreUser = in.readBoolean();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        resource.writeTo(out);
        out.writeBoolean(shouldStoreUser);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public SampleResource getResource() {
        return this.resource;
    }

    public boolean shouldStoreUser() {
        return this.shouldStoreUser;
    }

    @Override
    public String index() {
        return RESOURCE_INDEX_NAME;
    }

    @Override
    public String id() {
        return null;
    }

    @Override
    public String type() {
        return RESOURCE_TYPE;
    }
}
