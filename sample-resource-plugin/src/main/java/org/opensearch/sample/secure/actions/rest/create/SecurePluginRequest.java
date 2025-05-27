/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.secure.actions.rest.create;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

/**
 * Request object for SecurePluginAction transport action
 */
public class SecurePluginRequest extends ActionRequest {

    private final String action;
    private final String index;

    /**
     * Default constructor
     */
    public SecurePluginRequest(String action, String index) {
        this.action = action;
        this.index = index;
    }

    public SecurePluginRequest(StreamInput in) throws IOException {
        this.action = in.readString();
        this.index = in.readString();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(action);
        out.writeString(index);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getAction() {
        return this.action;
    }

    public String getIndex() {
        return this.index;
    }
}
