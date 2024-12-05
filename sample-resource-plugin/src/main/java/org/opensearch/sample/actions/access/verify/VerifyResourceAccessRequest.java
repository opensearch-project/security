/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.actions.access.verify;

import java.io.IOException;
import java.util.Set;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.sample.utils.Validation;

public class VerifyResourceAccessRequest extends ActionRequest {

    private final String resourceId;

    private final String scope;

    /**
     * Default constructor
     */
    public VerifyResourceAccessRequest(String resourceId, String scope) {
        this.resourceId = resourceId;
        this.scope = scope;
    }

    /**
     * Constructor with stream input
     * @param in the stream input
     * @throws IOException IOException
     */
    public VerifyResourceAccessRequest(final StreamInput in) throws IOException {
        this.resourceId = in.readString();
        this.scope = in.readString();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(resourceId);
        out.writeString(scope);
    }

    @Override
    public ActionRequestValidationException validate() {
        return Validation.validateScopes(Set.of(scope));
    }

    public String getResourceId() {
        return resourceId;
    }

    public String getScope() {
        return scope;
    }
}
