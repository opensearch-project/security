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
import org.opensearch.sample.SampleResourceGroup;

import static org.opensearch.sample.utils.Constants.RESOURCE_GROUP_TYPE;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Request object for UpdateResourceGroup transport action
 */
public class UpdateResourceGroupRequest extends ActionRequest implements DocRequest {

    private final String resourceId;
    private final SampleResourceGroup resourceGroup;

    /**
     * Default constructor
     */
    public UpdateResourceGroupRequest(String resourceId, SampleResourceGroup resourceGroup) {
        this.resourceId = resourceId;
        this.resourceGroup = resourceGroup;
    }

    public UpdateResourceGroupRequest(StreamInput in) throws IOException {
        this.resourceId = in.readString();
        this.resourceGroup = in.readNamedWriteable(SampleResourceGroup.class);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(resourceId);
        resourceGroup.writeTo(out);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public SampleResourceGroup getResource() {
        return this.resourceGroup;
    }

    public String getResourceId() {
        return this.resourceId;
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
        return resourceId;
    }
}
