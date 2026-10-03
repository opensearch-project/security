/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.get;

import java.io.IOException;
import java.util.List;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.spi.resources.MultiResourceRequest;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;

/**
 * Request object for MultiGetSampleResource transport action. Names several resources in one request, so it reports its
 * ids through {@link MultiResourceRequest#ids()} and the security plugin authorizes every one of them.
 */
public class MultiGetResourceRequest extends ActionRequest implements MultiResourceRequest {

    private final List<String> resourceIds;

    /**
     * Default constructor
     */
    public MultiGetResourceRequest(List<String> resourceIds) {
        this.resourceIds = resourceIds;
    }

    public MultiGetResourceRequest(StreamInput in) throws IOException {
        this.resourceIds = in.readStringList();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeStringCollection(this.resourceIds);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public String type() {
        return RESOURCE_TYPE;
    }

    @Override
    public String index() {
        return RESOURCE_INDEX_NAME;
    }

    @Override
    public List<String> ids() {
        return resourceIds;
    }
}
