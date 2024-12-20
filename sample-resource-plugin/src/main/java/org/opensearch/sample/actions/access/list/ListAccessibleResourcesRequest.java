/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.access.list;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

/**
 * Request object for ListSampleResource transport action
 */
public class ListAccessibleResourcesRequest extends ActionRequest {

    public ListAccessibleResourcesRequest() {}

    /**
     * Constructor with stream input
     * @param in the stream input
     * @throws IOException IOException
     */
    public ListAccessibleResourcesRequest(final StreamInput in) throws IOException {}

    @Override
    public void writeTo(final StreamOutput out) throws IOException {}

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }
}
