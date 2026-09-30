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

import static org.opensearch.sample.utils.Constants.RESOURCE_BY_NAME_REQUEST_TYPE;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Request object for GetSampleResourceByName transport action. It names a resource by name, so the id of the resource
 * that governs access is only known after a lookup; the plugin's {@code GatingResourceResolver} performs it and the
 * security plugin authorizes the resource it names.
 */
public class GetResourceByNameRequest extends ActionRequest implements DocRequest {

    private final String resourceName;

    /**
     * Default constructor
     */
    public GetResourceByNameRequest(String resourceName) {
        this.resourceName = resourceName;
    }

    public GetResourceByNameRequest(StreamInput in) throws IOException {
        this.resourceName = in.readString();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(this.resourceName);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getResourceName() {
        return this.resourceName;
    }

    @Override
    public String type() {
        return RESOURCE_BY_NAME_REQUEST_TYPE;
    }

    @Override
    public String index() {
        return RESOURCE_INDEX_NAME;
    }

    @Override
    public String id() {
        return resourceName;
    }
}
