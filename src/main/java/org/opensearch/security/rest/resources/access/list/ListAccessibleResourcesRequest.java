/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.rest.resources.access.list;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

/**
 * Request object for ListSampleResource transport action
 */
public class ListAccessibleResourcesRequest extends ActionRequest {

    private String resourceIndex;

    public ListAccessibleResourcesRequest(String resourceIndex) {
        this.resourceIndex = resourceIndex;
    }

    /**
     * Constructor with stream input
     * @param in the stream input
     * @throws IOException IOException
     */
    public ListAccessibleResourcesRequest(final StreamInput in) throws IOException {
        this.resourceIndex = in.readString();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(this.resourceIndex);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getResourceIndex() {
        return resourceIndex;
    }
}
