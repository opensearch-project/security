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
    // Set by the resolver on the node that authorizes the request, so the action serves exactly the resource authorized.
    // Not serialized: a request that reaches the action without it falls back to the name lookup.
    private volatile String resolvedResourceId;

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

    /**
     * @return the id the gating resolver resolved the name to, or {@code null} if the request was not resolved
     */
    public String getResolvedResourceId() {
        return this.resolvedResourceId;
    }

    /**
     * Records the id the gating resolver resolved the name to, which is the resource the security plugin authorizes.
     *
     * @param resourceId the resolved resource id
     */
    public void setResolvedResourceId(String resourceId) {
        this.resolvedResourceId = resourceId;
    }

    @Override
    public String type() {
        return RESOURCE_BY_NAME_REQUEST_TYPE;
    }

    @Override
    public String index() {
        return RESOURCE_INDEX_NAME;
    }

    /**
     * No id of its own: the resource is addressed by name, and its id is only known after the lookup the plugin's
     * {@code GatingResourceResolver} performs. This is the shape a create has as well, where the document does not exist
     * yet.
     */
    @Override
    public String id() {
        return null;
    }
}
