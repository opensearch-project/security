/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.get;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.DocRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Request object for GetSampleResource transport action
 */
public class GetResourceRequest extends ActionRequest implements DocRequest {

    private final String resourceId;

    /**
     * Default constructor
     */
    public GetResourceRequest(String resourceId) {
        this.resourceId = resourceId;
    }

    public GetResourceRequest(StreamInput in) throws IOException {
        this.resourceId = in.readString();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(this.resourceId);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getResourceId() {
        return this.resourceId;
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
