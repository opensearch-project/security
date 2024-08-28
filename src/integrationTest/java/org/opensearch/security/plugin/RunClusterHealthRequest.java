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

    private final String runActionAs;

    public RunClusterHealthRequest(String runActionAs) {
        this.runActionAs = runActionAs;
    }

    public RunClusterHealthRequest(StreamInput in) throws IOException {
        super(in);
        this.runActionAs = in.readString();
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getRunActionAs() {
        return runActionAs;
    }
}
