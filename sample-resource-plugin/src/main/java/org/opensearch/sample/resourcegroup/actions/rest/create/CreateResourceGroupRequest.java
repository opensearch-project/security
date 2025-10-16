/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup.actions.rest.create;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.DocRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.sample.SampleResource;

import static org.opensearch.sample.utils.Constants.RESOURCE_GROUP_TYPE;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Request object for CreateSampleResourceGroup transport action
 */
public class CreateResourceGroupRequest extends ActionRequest implements DocRequest {

    private final SampleResource resource;

    /**
     * Default constructor
     */
    public CreateResourceGroupRequest(SampleResource resource) {
        this.resource = resource;
    }

    public CreateResourceGroupRequest(StreamInput in) throws IOException {
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

    @Override
    public String type() {
        return RESOURCE_GROUP_TYPE;
    }

    @Override
    public String index() {
        return RESOURCE_INDEX_NAME;
    }

    @Override
    public String id() {
        return null;
    }
}
