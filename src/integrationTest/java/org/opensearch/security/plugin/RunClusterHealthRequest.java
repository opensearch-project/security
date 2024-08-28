/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.plugin;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;

public class RunClusterHealthRequest extends ActionRequest {

    private final String runAs;

    public RunClusterHealthRequest(String runAs) {
        this.runAs = runAs;
    }

    public RunClusterHealthRequest(StreamInput in) throws IOException {
        super(in);
        this.runAs = in.readString();
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getRunAs() {
        return this.runAs;
    }
}
